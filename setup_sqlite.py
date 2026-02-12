import sqlite3

# Connect to SQLite database (it will create the file if it doesn't exist)
conn = sqlite3.connect('quizapp.db')
cursor = conn.cursor()

# Read and execute the SQL file
with open('quizapp_sqlite.sql', 'r') as file:
    sql_script = file.read()

# Split the script into individual statements
statements = sql_script.split(';')

for statement in statements:
    if statement.strip():
        cursor.execute(statement)

# Insert a default user for testing
cursor.execute('''
INSERT INTO users (name, email, password, user_type, user_image, user_login, examcredits)
VALUES (?, ?, ?, ?, ?, ?, ?)
''', ('Admin', 'admin@example.com', 'password', 'teacher', '', 0, 10))

conn.commit()
cursor.close()
conn.close()

print("SQLite database setup completed successfully!")
print("Default user: email=admin@example.com, password=password, type=teacher")
