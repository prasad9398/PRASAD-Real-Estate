import mysql.connector
import pandas as pd

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'YOUR PASSWORD',  
    'database': 'real_estate'
}

def query_to_csv(query, filename):
    conn = mysql.connector.connect(**db_config)
    df = pd.read_sql(query, conn)
    df.to_csv(f"exports/{filename}.csv", index=False)
    conn.close()
    print(f" Exported: {filename}.csv")

import os
os.makedirs("exports", exist_ok=True)

query_avg_price = """
SELECT 
    city, 
    state, 
    AVG(price) AS avg_listing_price, 
    COUNT(*) AS property_count
FROM Properties
GROUP BY city, state
ORDER BY avg_listing_price DESC;
"""
query_to_csv(query_avg_price, "avg_price_by_region")

query_high_demand = "SELECT * FROM HighDemandAreas;"
query_to_csv(query_high_demand, "high_demand_areas")

query_trends = """
SELECT 
    p.city, 
    t.sale_date, 
    t.sale_price,
    AVG(t.sale_price) OVER (PARTITION BY p.city ORDER BY t.sale_date 
                            ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) AS moving_avg_3day
FROM Transactions t
JOIN Properties p ON t.property_id = p.property_id
ORDER BY p.city, t.sale_date;
"""
query_to_csv(query_trends, "price_trends")

query_properties = "SELECT * FROM Properties;"
query_to_csv(query_properties, "properties_list")

query_transactions = "SELECT * FROM Transactions;"
query_to_csv(query_transactions, "transactions")
