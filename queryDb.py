import sqlite3

# Reconnect to the database
conn = sqlite3.connect('nmap_data.db')
cursor = conn.cursor()

# Query all data from the table
cursor.execute('SELECT * FROM nmap_records')

# Fetch all rows from the result
rows = cursor.fetchall()

# Display the rows
for row in rows:
    print(row)

# Close the connection
conn.close()
