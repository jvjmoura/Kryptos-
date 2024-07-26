import streamlit as st
import fitz  # PyMuPDF
from typing import List, Tuple
import spacy
import re

# Set page config at the very beginning
st.set_page_config(layout="wide", page_title="Kryptos - Removedor de Dados Sensíveis", page_icon="🔒")

# Custom CSS to improve the visual aspect, including dark mode considerations
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
    }
    .stTextArea>div>div>textarea {
        background-color: var(--text-area-bg);
        color: var(--text-color);
    }
    .custom-alert {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .custom-alert.info {
        background-color: var(--info-bg);
        border-left: 6px solid #2196F3;
        color: var(--info-color);
    }
    .custom-alert.warning {
        background-color: var(--warning-bg);
        border-left: 6px solid #ffa000;
        color: var(--warning-color);
    }
    .logo-text {
        font-size: 24px;
        font-weight: bold;
        margin-left: 10px;
    }
    .logo-container {
        display: flex;
        align-items: center;
        margin-bottom: 20px;
    }
    </style>

    <script>
        var body = window.parent.document.querySelector('body');
        var isDark = body.classList.contains('dark');
        
        function updateColors() {
            var root = window.parent.document.querySelector(':root');
            if (isDark) {
                root.style.setProperty('--text-area-bg', '#2b2b2b');
                root.style.setProperty('--text-color', '#ffffff');
                root.style.setProperty('--info-bg', '#1e3a5f');
                root.style.setProperty('--info-color', '#e7f3fe');
                root.style.setProperty('--warning-bg', '#5f4d1e');
                root.style.setProperty('--warning-color', '#fff3cd');
            } else {
                root.style.setProperty('--text-area-bg', '#f0f2f6');
                root.style.setProperty('--text-color', '#000000');
                root.style.setProperty('--info-bg', '#e7f3fe');
                root.style.setProperty('--info-color', '#0c5460');
                root.style.setProperty('--warning-bg', '#fff3cd');
                root.style.setProperty('--warning-color', '#856404');
            }
        }
        
        updateColors();
        
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === "attributes" && mutation.attributeName === "class") {
                    isDark = body.classList.contains('dark');
                    updateColors();
                }
            });
        });
        
        observer.observe(body, {
            attributes: true
        });
    </script>
    """, unsafe_allow_html=True)

# Carregar o modelo spaCy para português
@st.cache_resource
def load_spacy_model():
    return spacy.load("pt_core_news_sm")

nlp = load_spacy_model()

# Lista atualizada e expandida de padrões de dados sensíveis
SENSITIVE_PATTERNS = {
    'CPF': r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b',
    'RG': r'\b\d{1,2}\.?\d{3}\.?\d{3}[-\s]?[0-9X]\b',
    'Data de Nascimento': r'\b\d{2}/\d{2}/\d{4}\b',
    'Telefone': r'\b(\(?\d{2}\)?\s?)?(\d{4,5}[-.\s]?\d{4})\b',
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'CEP': r'\b\d{5}-?\d{3}\b',
    'Endereço': r'\b(Rua|Avenida|Alameda|Travessa|Praça|Estrada)\s+[A-Za-zÀ-ÿ\s]+,?\s+n?º?\s*\d+\b',
    'Processo': r'\b\d{7}-?\d{2}\.?\d{4}\.?\d\.?\d{2}\.?\d{4}\b',
    'Nome Completo': r'\b[A-ZÀ-Ÿ][a-zà-ÿ]+(\s+[A-ZÀ-Ÿ][a-zà-ÿ]+){1,}\b'
}

# Palavras-chave expandidas para identificar vítimas, testemunhas, réus e denunciados
ROLE_KEYWORDS = {
    'Vítima': ['vítima', 'ofendido', 'ofendida', 'querelante', 'lesado', 'lesada'],
    'Testemunha': ['testemunha', 'depoente', 'declarante'],
    'Réu': ['réu', 'ré', 'acusado', 'acusada', 'indiciado', 'indiciada'],
    'Denunciado': ['denunciado', 'denunciada', 'investigado', 'investigada']
}

def identify_sensitive_data(text: str) -> List[Tuple[str, str, int, int]]:
    doc = nlp(text)
    sensitive_data = []
    
    # Identificar entidades nomeadas (nomes de pessoas, organizações e locais)
    for ent in doc.ents:
        if ent.label_ == "PER":
            role = "Nome"
            # Verificar se o nome está associado a uma função específica
            context = doc[max(0, ent.start-10):min(len(doc), ent.end+10)].text.lower()
            for role_type, keywords in ROLE_KEYWORDS.items():
                if any(keyword in context for keyword in keywords):
                    role = role_type
                    break
            sensitive_data.append((ent.text, role, ent.start_char, ent.end_char))
        elif ent.label_ in ["ORG", "LOC"]:
            sensitive_data.append((ent.text, ent.label_, ent.start_char, ent.end_char))
    
    # Identificar padrões específicos
    for label, pattern in SENSITIVE_PATTERNS.items():
        for match in re.finditer(pattern, text):
            sensitive_data.append((match.group(), label, match.start(), match.end()))
    
    return sensitive_data

def redact_sensitive_data(text: str, sensitive_data: List[Tuple[str, str, int, int]]) -> str:
    # Ordenar os dados sensíveis do final para o início para evitar problemas de indexação
    sensitive_data.sort(key=lambda x: x[2], reverse=True)
    
    for data, label, start, end in sensitive_data:
        replacement = f'[{label} REMOVIDO]'
        text = text[:start] + replacement + text[end:]
    
    return text

def process_text(text: str) -> str:
    sensitive_data = identify_sensitive_data(text)
    redacted_text = redact_sensitive_data(text, sensitive_data)
    return redacted_text

def extract_text_from_pdf(pdf_file) -> str:
    pdf_document = fitz.open(stream=pdf_file.read(), filetype="pdf")
    all_text = ""
    for page in pdf_document:
        all_text += page.get_text()
    return all_text

def main():
    # Logo
    st.sidebar.image("https://cdn.midjourney.com/152d6718-a07d-443f-9a33-ea0ee9b84cf0/0_3.png", width=200)

    st.title('Kryptos: Removedor de Dados Sensíveis para Documentos Judiciais')

    # Sidebar
    st.sidebar.title("Como usar o Kryptos")
    st.sidebar.markdown("""
    1. Escolha entre inserir o texto diretamente ou fazer upload de um arquivo.
    2. Se inserir o texto, clique no botão "Anonimizar Texto" após a inserção.
    3. Se fizer upload de um arquivo, o processamento começará automaticamente.
    4. Revise o texto anonimizado na área de texto.
    5. Copie o texto anonimizado ou faça o download, se disponível.
    6. Sempre faça uma revisão manual final para garantir a remoção completa dos dados sensíveis.

    **Responsável pela ferramenta:**
    João Valério
    Cargo: Juiz de Direito
    Email: joao.moura@tjpa.jus.br

    **Importante:** Esta ferramenta é um auxílio na anonimização de documentos. 
    Sempre faça uma revisão manual final para garantir a proteção adequada dos dados sensíveis.
    """)

    # Advertência (versão melhorada)
    st.markdown("""
    <div class="custom-alert warning">
        <h4>⚠️ Atenção ao Uso</h4>
        <p>Para fins de teste desta ferramenta, utilize apenas dados sensíveis fictícios. 
        A inserção de informações reais ou confidenciais é estritamente desaconselhada.</p>
    </div>
    """, unsafe_allow_html=True)

    # Tabs para diferentes opções de entrada
    tab1, tab2 = st.tabs(["Inserir Texto", "Upload de Arquivo"])

    with tab1:
        st.subheader("Inserir texto diretamente")
        input_text = st.text_area("Cole ou digite o texto a ser anonimizado aqui:", height=200, 
                                  help="Insira o texto que você deseja anonimizar nesta área.")
        if st.button("Anonimizar Texto", help="Clique para iniciar o processo de anonimização"):
            if input_text:
                with st.spinner('Processando e anonimizando o texto...'):
                    anonymized_text = process_text(input_text)
                    st.success("Texto processado e anonimizado com sucesso!")
                    st.text_area("Texto anonimizado:", anonymized_text, height=400)
                    
                    # Opção para download do texto anonimizado
                    st.download_button(
                        label="Download do texto anonimizado",
                        data=anonymized_text,
                        file_name="documento_anonimizado.txt",
                        mime="text/plain",
                        help="Clique para baixar o texto anonimizado como um arquivo .txt"
                    )
            else:
                st.error("Por favor, insira algum texto antes de anonimizar.")

    with tab2:
        st.subheader("Fazer upload de arquivo")
        uploaded_file = st.file_uploader("Escolha um arquivo (PDF ou TXT)", type=["pdf", "txt"], 
                                         help="Selecione um arquivo PDF ou TXT para anonimizar")

        if uploaded_file is not None:
            with st.spinner('Extraindo e processando o texto do documento...'):
                if uploaded_file.type == "application/pdf":
                    extracted_text = extract_text_from_pdf(uploaded_file)
                else:
                    extracted_text = uploaded_file.getvalue().decode('utf-8')
                
                # Aplicar o processo de anonimização
                anonymized_text = process_text(extracted_text)
                
                st.success("Documento processado e anonimizado com sucesso!")
                st.text_area("Texto anonimizado:", anonymized_text, height=400)
                
                # Opção para download do texto anonimizado
                st.download_button(
                    label="Download do texto anonimizado",
                    data=anonymized_text,
                    file_name="documento_anonimizado.txt",
                    mime="text/plain",
                    help="Clique para baixar o texto anonimizado como um arquivo .txt"
                )

    st.markdown("---")
    
    # Informação sobre responsabilidade compartilhada (versão melhorada)
    st.markdown("""
    <div class="custom-alert info">
        <h4>📌 Dicas de Uso e Responsabilidade Compartilhada</h4>
        <ul>
            <li>O Kryptos foi otimizado para documentos judiciais, mas requer revisão manual.</li>
            <li>Comece com pequenos trechos para se familiarizar com a ferramenta.</li>
            <li>Verifique cuidadosamente o resultado da anonimização.</li>
            <li>Para documentos extensos, considere dividi-los em partes menores.</li>
            <li>A segurança dos dados é uma responsabilidade compartilhada. Use esta ferramenta como auxílio, mas confie em sua revisão final.</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
