import streamlit as st
import pandas as pd
import re
import requests
from collections import Counter
from datetime import datetime
import logging  
from db_connection import create_connection 

# ==========================
# CONFIGURAÇÃO DA PÁGINA
# ==========================

st.set_page_config(
    page_title="Brute Force Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cyber Security Dashboard")
st.markdown("---")

if st.button("🔄 Atualizar Logs"):
    st.rerun()

# ==========================
# CONFIGURAÇÃO DE AUDITORIA (LOGGING)
# ==========================

logging.basicConfig(
    filename="erros_aplicacao.log",                    
    level=logging.ERROR,                               
    format="%(asctime)s | %(levelname)s | %(message)s", 
    datefmt="%Y-%m-%d %H:%M:%S"
)
# ==========================
# CAMADA DE AUTENTICAÇÃO SOC
# ==========================

def realizar_login():
    if "autenticado" not in st.session_state:
        st.session_state["autenticado"] = False

    if not st.session_state["autenticado"]:
        st.subheader("🔑 Acesso Restrito - Cyber Security SOC")
        usuario_soc = st.text_input("Usuário Analista:")
        senha_soc = st.text_input("Senha de Acesso:", type="password")
        
        if st.button("Entrar no Painel"):
            # Exemplo simples de credenciais (em produção, use hash ou tabela de usuários)
            if usuario_soc == "analista_soc" and senha_soc == "SOC_Secure2026!":
                st.session_state["autenticado"] = True
                st.success("Autenticado com sucesso!")
                st.rerun()
            else:
                st.error("Credenciais inválidas. Tentativa negada.")
        return False
    return True

# Executa a trava de tela se o usuário não estiver logado
if not realizar_login():
    st.stop()  # Interrompe a renderização do dashboard aqui se não logar

# ==========================
# INICIALIZAÇÃO DO BANCO DE DADOS
# ==========================

conn = create_connection()

if conn and conn.is_connected():
    cursor = conn.cursor()
    # Cria a tabela no formato MySQL se não existir
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ataques (
        id INT AUTO_INCREMENT PRIMARY KEY,
        data_hora VARCHAR(50),
        usuario VARCHAR(100),
        ip VARCHAR(45),
        evento VARCHAR(50)
    )
    """)
    conn.commit()
else:
    st.error("❌ Não foi possível conectar ao banco de dados MySQL em localhost. Verifique o serviço.")
    st.stop()

# ==========================
# LEITURA DO LOG
# ==========================

try:
    with open("auth.log", "r", encoding="utf-8", errors="ignore") as arquivo:
        log_data = arquivo.readlines()
except FileNotFoundError:
    st.error("❌ Arquivo 'auth.log' não encontrado.")
    log_data = []

# ==========================
# EXTRAÇÃO E CARGA NO BANCO
# ==========================

eventos = []
sucessos = []

for linha in log_data:
    # FALHAS DE LOGIN
    if "Failed password" in linha:
        data_hora = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', linha)
        usuario = re.search(r'Failed password for (\w+)', linha)
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', linha)

        dt_hr = data_hora.group(1) if data_hora else "N/A"
        user = usuario.group(1) if usuario else "N/A"
        ip_origem = ip.group(1) if ip else "N/A"

        # 🎭 MASCARAMENTO DE IP SEGURO 
        # Recupera os valores configurados de forma oculta
        ip_kali = st.secrets["mascaramento"]["ip_vm_kali"] if "mascaramento" in st.secrets else "N/A"
        ip_local = st.secrets["mascaramento"]["ip_host_local"] if "mascaramento" in st.secrets else "N/A"

        # Faz a validação sem expor os números reais no código fonte
        if ip_origem == ip_kali: 
            ip_addr = "8.8.8.8"        # Simula tráfego vindo dos EUA
        elif ip_origem == ip_local or ip_origem == "127.0.0.1":
            ip_addr = "185.220.101.5"  # Simula nó de saída Tor na Alemanha
        else:
            ip_addr = ip_origem

        eventos.append({
            "Data/Hora": dt_hr,
            "Hora": dt_hr.split()[-1][:5] if data_hora else "N/A",
            "Usuário": user,
            "IP": ip_addr, 
            "Evento": "Failed Password"
        })

        # CARGA AUTOMÁTICA NO BANCO: Evita duplicar registros idênticos
        try:
            cursor.execute(
                "SELECT id FROM ataques WHERE data_hora = %s AND usuario = %s AND ip = %s", 
                (dt_hr, user, ip_addr)
            )
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO ataques (data_hora, usuario, ip, evento)
                    VALUES (%s, %s, %s, %s)
                """, (dt_hr, user, ip_addr, "Failed Password"))
                conn.commit()
        except Exception as e:
            # 🚨 EM VEZ DE 'PASS', AGORA AUDITAMOS O ERRO REAL SILENCIOSAMENTE NO LOG LOCAL
            logging.error(f"Falha ao inserir registro no MySQL (IP: {ip_addr}, Usuário: {user}). Erro técnico: {str(e)}")

    # SUCESSOS DE LOGIN
    elif "Accepted password" in linha:
        data_hora = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', linha)
        usuario = re.search(r'Accepted password for (\w+)', linha)
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', linha)

        sucessos.append({
            "Data/Hora": data_hora.group(1) if data_hora else "N/A",
            "Usuário": usuario.group(1) if usuario else "N/A",
            "IP": ip.group(1) if ip else "N/A"
        })

# Criação segura do DataFrame principal baseado nos eventos atuais do log
df = pd.DataFrame(eventos) if eventos else pd.DataFrame(columns=["Data/Hora", "Hora", "Usuário", "IP", "Evento"])

# ==========================
# GEOLOCALIZAÇÃO (COM CACHE APLICADO)
# ==========================

@st.cache_data(ttl=86400) # Evita estourar o limite da API (guarda por 24h)
def obter_localizacao(ip):
    try:
        resposta = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        dados = resposta.json()
        if dados["status"] == "success":
            return {
                "IP": ip,
                "País": dados["country"],
                "Cidade": dados["city"],
                "Latitude": dados["lat"],
                "Longitude": dados["lon"]
            }
    except:
        pass
    return None

# ==========================
# FILTROS DA INTERFACE
# ==========================

df_filtrado = df.copy()

if not df_filtrado.empty:
    lista_ips = ["Todos"] + sorted(df_filtrado["IP"].unique().tolist())
    ip_selecionado = st.selectbox("🔍 Filtrar por IP", lista_ips)
    if ip_selecionado != "Todos":
        df_filtrado = df_filtrado[df_filtrado["IP"] == ip_selecionado]

    lista_usuarios = ["Todos"] + sorted(df_filtrado["Usuário"].unique().tolist())
    usuario_selecionado = st.selectbox("👤 Filtrar por Usuário", lista_usuarios)
    if usuario_selecionado != "Todos":
        df_filtrado = df_filtrado[df_filtrado["Usuário"] == usuario_selecionado]

# ==========================
# CONTAGEM E MÉTRICAS
# ==========================

contador = Counter(df_filtrado["IP"]) if not df_filtrado.empty else {}

possiveis_comprometimentos = []
for sucesso in sucessos:
    ip = sucesso["IP"]
    falhas = contador.get(ip, 0)
    if falhas >= 3:
        possiveis_comprometimentos.append({
            "IP": ip,
            "Usuário": sucesso["Usuário"],
            "Falhas": falhas
        })

top_ip, top_tentativas = (None, 0)
nivel_risco = "Nenhum"

if contador:
    top_ip, top_tentativas = contador.most_common(1)[0]
    if top_tentativas <= 2: nivel_risco = "🟢 Baixo"
    elif top_tentativas <= 5: nivel_risco = "🟡 Médio"
    elif top_tentativas <= 10: nivel_risco = "🟠 Alto"
    else: nivel_risco = "🔴 Crítico"

col1, col2, col3 = st.columns(3)
col1.metric(label="Total de Falhas SSH", value=len(df_filtrado))
col2.metric(label="IPs Suspeitos", value=len(contador))
col3.metric(label="🔥 Top Atacante", value=top_ip if top_ip else "Nenhum", delta=f"{top_tentativas} tentativas" if top_ip else "")

st.markdown("---")
st.subheader("🎯 Avaliação de Risco")
if top_ip:
    st.info(f"**IP Mais Ativo:** {top_ip}  \n**Tentativas:** {top_tentativas}  \n**Nível de Risco:** {nivel_risco}")

# ==========================
# ALERTAS
# ==========================

st.subheader("🚨 Alertas")
if contador:
    alerta_encontrado = False
    for ip, tentativas in contador.items():
        if tentativas >= 3:
            alerta_encontrado = True
            st.error(f"🚨 BRUTE FORCE DETECTADO | IP: {ip} | Falhas: {tentativas}")
    if not alerta_encontrado:
        st.success("Nenhum brute force detectado.")
else:
    st.success("Nenhum evento suspeito encontrado.")

# ==========================
# POSSÍVEL COMPROMETIMENTO
# ==========================

if possiveis_comprometimentos:
    st.subheader("🔓 Possível Comprometimento")
    for evento in possiveis_comprometimentos:
        st.error(f"🚨 **POSSÍVEL COMPROMETIMENTO DE CONTA** \n\n**IP:** {evento['IP']}  \n**Usuário:** {evento['Usuário']}  \n**Falhas antes do login:** {evento['Falhas']}")

# ==========================
# GRÁFICOS E TIMELINE
# ==========================

st.subheader("📊 Ataques por IP")
if contador:
    grafico_df = pd.DataFrame(contador.items(), columns=["IP", "Tentativas"])
    st.bar_chart(grafico_df.set_index("IP"))
else:
    st.info("Sem dados para exibir.")

st.subheader("📈 Linha do Tempo dos Ataques")
if not df_filtrado.empty:
    timeline = df_filtrado.groupby("Hora").size().reset_index(name="Tentativas")
    st.line_chart(timeline.set_index("Hora"))
else:
    st.info("Sem dados para exibir.")

# ==========================
# TOP 10 ATACANTES
# ==========================

st.subheader("🏆 Top 10 Atacantes")
if contador:
    top_df = pd.DataFrame(contador.items(), columns=["IP", "Tentativas"]).sort_values(by="Tentativas", ascending=False).head(10)
    st.dataframe(top_df, use_container_width=True)
    st.bar_chart(top_df.set_index("IP"))
else:
    st.info("Nenhum atacante encontrado.")

# ==========================
# MAPA DE ATAQUES
# ==========================

st.subheader("🌍 Origem dos Ataques")
dados_mapa = []
for ip in contador.keys():
    localizacao = obter_localizacao(ip)
    if localizacao: dados_mapa.append(localizacao)

if dados_mapa:
    mapa_df = pd.DataFrame(dados_mapa)
    st.dataframe(mapa_df, use_container_width=True)
    st.map(mapa_df.rename(columns={"Latitude": "lat", "Longitude": "lon"}))
else:
    st.info("Nenhuma localização externa encontrada.")

# ==========================
# RELATÓRIO SOC
# ==========================

st.subheader("📄 Relatório SOC")
if st.button("📄 Gerar Relatório SOC"):
    relatorio = f"RELATÓRIO DE INCIDENTE DE SEGURANÇA\nData: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
    relatorio += f"Total de Falhas: {len(df_filtrado)}\nIP Mais Ativo: {top_ip}\nNível de Risco: {nivel_risco}"
    st.text_area("Relatório Gerado", relatorio, height=200)
    st.download_button(label="📥 Baixar Relatório TXT", data=relatorio, file_name="relatorio_soc.txt")

# ==========================
# HISTÓRICO ACUMULADO (MYSQL) WITH SEARCH
# ==========================

st.subheader("🗄️ Histórico de Ataques (MySQL)")

busca_banco = st.text_input("🔍 Buscar no banco por IP ou Usuário específico:")

try:

    if busca_banco:
        query_busca = """
            SELECT * FROM ataques 
            WHERE ip LIKE %s OR usuario LIKE %s 
            ORDER BY id DESC LIMIT 100
        """
        historico = pd.read_sql_query(query_busca, conn, params=(f"%{busca_banco}%", f"%{busca_banco}%"))
    else:
        historico = pd.read_sql_query("SELECT * FROM ataques ORDER BY id DESC LIMIT 100", conn)
        
    st.dataframe(historico, use_container_width=True)
except Exception as e:
    st.error(f"Erro ao ler histórico: {e}")
    # 📄 Registra no arquivo de auditoria técnica local
    logging.error(f"Falha crítica na consulta do Histórico MySQL. Detalhes: {str(e)}")

# ==========================
# EXPORTAR CSV E TABELA FINAL
# ==========================

st.subheader("📥 Exportar Relatório")
if not df_filtrado.empty:
    # Criação que gerar o CSV sob demanda
    def converter_para_csv(df):
        return df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📥 Baixar Relatório CSV", 
        data=converter_para_csv(df_filtrado), 
        file_name="eventos_bruteforce.csv", 
        mime="text/csv"
    )
st.subheader("📋 Eventos Detectados")
if not df_filtrado.empty:
    st.dataframe(df_filtrado, use_container_width=True)
else:
    st.info("Nenhum evento encontrado no log.")