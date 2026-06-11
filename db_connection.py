# db_connection.py
# db_connection.py
import mysql.connector
from mysql.connector import Error
import streamlit as st

@st.cache_resource  # Evita reabrir a conexão a cada clique na tela
def create_connection():
    try:
        if "mysql" in st.secrets:
            connection = mysql.connector.connect(
                host=st.secrets["mysql"]["host"],
                user=st.secrets["mysql"]["user"],
                password=st.secrets["mysql"]["password"],
                database=st.secrets["mysql"]["database"]
            )
            if connection.is_connected():
                return connection
        else:
            
            print("❌ Configurações do MySQL não encontradas no st.secrets.")
            return None

    except Error as e:
        print(f"❌ Erro ao conectar no MySQL: {e}")
        return None