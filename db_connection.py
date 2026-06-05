# db_connection.py
# db_connection.py
import mysql.connector
from mysql.connector import Error
import streamlit as st

def create_connection():
    try:
        # O Streamlit lê o arquivo secrets.toml automaticamente se estiver rodando o app
        if "mysql" in st.secrets:
            connection = mysql.connector.connect(
                host=st.secrets["mysql"]["host"],
                user=st.secrets["mysql"]["user"],
                password=st.secrets["mysql"]["password"],
                database=st.secrets["mysql"]["database"]
            )
        else:
            # Fallback seguro caso rode um script isolado de teste via terminal
            connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="Kazaky35!",
                database="bf_dashboard"
            )

        if connection.is_connected():
            return connection

    except Error as e:
        print(f"❌ Erro ao conectar no MySQL: {e}")
        return None