import pymysql

# Connect without database to create it
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    port=3306
)

cursor = connection.cursor()

# Create database if not exists
cursor.execute("CREATE DATABASE IF NOT EXISTS quizapp")

# Use the database
cursor.execute("USE quizapp")

# Read and execute the SQL file
with open('DB/quizappstructure.sql', 'r') as file:
    sql_script = file.read()

# Split the script into individual statements
statements = sql_script.split(';')

for statement in statements:
    if statement.strip():
        cursor.execute(statement)

connection.commit()
cursor.close()
connection.close()

print("Database setup completed successfully!")
