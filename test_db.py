import pymysql

try:
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='root',
        database='quizapp',
        port=3306
    )
    print("Database connected successfully!")
    connection.close()
except Exception as e:
    print(f"Error connecting to database: {e}")
