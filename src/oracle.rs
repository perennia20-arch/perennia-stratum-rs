<file path="src/oracle.rs">
        // 2. Bulk Aggregated Upsert into Yield Reservoirs
        let mut agg_wallets = Vec::with_capacity(wallet_aggregates.len());
        let mut agg_deltas = Vec::with_capacity(wallet_aggregates.len());
        
        for (w, d) in wallet_aggregates {
            agg_wallets.push(w);
            agg_deltas.push(d);
        }

        if commit_success {
            let upsert_res = sqlx::query(
                r#"
                INSERT INTO yield_reservoirs (wallet_address, streaming_balance_kas, total_yield_kas)
                SELECT * FROM UNNEST($1::text[], $2::float8[], $2::float8[])
                ON CONFLICT (wallet_address)
                DO UPDATE SET
                    streaming_balance_kas = yield_reservoirs.streaming_balance_kas + EXCLUDED.streaming_balance_kas,
                    total_yield_kas = yield_reservoirs.total_yield_kas + EXCLUDED.total_yield_kas,
                    last_updated = CURRENT_TIMESTAMP
                "#
            )
            .bind(&agg_wallets).bind(&agg_deltas)
            .execute(&mut *tx).await;

            if upsert_res.is_err() { commit_success = false; }
        }

        // 3. 1099-DA Compliance Stamping (Gross Proceeds Ledger)
        if commit_success && !agg_wallets.is_empty() {
            // Fetch live spot price from Redis to stamp the financial event
            let kas_spot_price: f64 = redis::cmd("GET")
                .arg("oracle:spot:KAS_USDC")
                .query_async(&mut redis_conn)
                .await
                .unwrap_or(0.16); // Failsafe to static baseline if oracle desyncs

            let mut event_types = Vec::with_capacity(agg_wallets.len());
            let mut tickers = Vec::with_capacity(agg_wallets.len());
            let mut gross_proceeds = Vec::with_capacity(agg_wallets.len());
            let mut spot_prices = Vec::with_capacity(agg_wallets.len());

            for delta in &agg_deltas {
                event_types.push("YIELD");
                tickers.push("KAS");
                gross_proceeds.push(delta * kas_spot_price);
                spot_prices.push(kas_spot_price);
            }

            let tax_ledger_res = sqlx::query(
                r#"
                INSERT INTO tax_ledger_events 
                (wallet_address, asset_ticker, event_type, gross_proceeds_usd, amount_tokens, spot_price_at_execution)
                SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::float8[], $5::float8[], $6::float8[])
                "#
            )
            .bind(&agg_wallets)
            .bind(&tickers)
            .bind(&event_types)
            .bind(&gross_proceeds)
            .bind(&agg_deltas)
            .bind(&spot_prices)
            .execute(&mut *tx).await;

            if tax_ledger_res.is_err() { commit_success = false; }
        }
</file>