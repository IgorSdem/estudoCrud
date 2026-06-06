const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");

const app = express();

/* MIDDLEWARES */
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
    session({
        secret: "segredo123",
        resave: false,
        saveUninitialized: false
    })
);

/* CONEXÃO COM MYSQL */
const conexao = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "123456",
    database: "sistema_login"
});

conexao.connect((erro) => {
    if (erro) {
        console.log("Erro ao conectar ao banco:");
        console.log(erro);
        return;
    }
    console.log("Banco conectado com sucesso!");
});

/* ROTA INICIAL */
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* LOGIN */
app.post("/login", (req, res) => {
    console.log("Recebi requisição de login");

    const { email, senha } = req.body;

    const sql = "SELECT * FROM usuarios WHERE email = ? AND senha = ?";

    conexao.query(sql, [email, senha], (erro, resultado) => {
        if (erro) {
            console.log("Erro SQL:", erro);
            return res.send("Erro ao consultar banco");
        }

        if (resultado.length > 0) {
            console.log("Login válido");
            req.session.usuario = resultado[0];
            return res.redirect("/painel.html");
        }

        console.log("Login inválido");
        res.send("Usuário ou senha inválidos");
    });
});

/* DASHBOARD PROTEGIDO */
app.get("/dashboard", (req, res) => {
    if (!req.session.usuario) {
        return res.redirect("/");
    }
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

/* LOGOUT */
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

/* CADASTRAR USUÁRIO */
app.post('/cadastrar', (req, res) => {
    const { nome, email, senha } = req.body;
    const sql = 'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)';

    conexao.query(sql, [nome, email, senha], (err, resultado) => {
        if (err) {
            console.error('Erro ao inserir no banco de dados:', err);
            if (err.code === 'ER_DUP_ENTRY') {
                return res.send('<h1>Erro: Este e-mail já está cadastrado!</h1><a href="/cadastroUsuario.html">Tentar novamente</a>');
            }
            return res.status(500).send('<h1>Erro interno ao salvar o usuário.</h1>');
        }

        res.send(`
            <script>
                alert('Usuário cadastrado com sucesso!');
                window.location.href = '/painel.html';
            </script>
        `);
    });
});

/* ATUALIZAR USUÁRIO */
app.post('/atualizar', (req, res) => {
    const { emailAtual, novoNome, novaSenha } = req.body;
    const sql = 'UPDATE usuarios SET nome = ?, senha = ? WHERE email = ?';

    conexao.query(sql, [novoNome, novaSenha, emailAtual], (err, resultado) => {
        if (err) {
            console.error('Erro ao atualizar no banco de dados:', err);
            return res.status(500).send('<h1>Erro interno ao atualizar o usuário.</h1>');
        }

        if (resultado.affectedRows === 0) {
            return res.send(`
                <script>
                    alert('Erro: Nenhum usuário encontrado com o e-mail informado.');
                    window.location.href = '/atualizarUsuario.html';
                </script>
            `);
        }

        res.send(`
            <script>
                alert('Dados atualizados com sucesso!');
                window.location.href = '/painel.html';
            </script>
        `);
    });
});

/* DELETAR USUÁRIO */
app.post('/deletar', (req, res) => {
    const { emailDeletar } = req.body;
    const sql = 'DELETE FROM usuarios WHERE email = ?';

    conexao.query(sql, [emailDeletar], (err, resultado) => {
        if (err) {
            console.error('Erro ao deletar no banco de dados:', err);
            return res.status(500).send('<h1>Erro interno ao deletar o usuário.</h1>');
        }

        if (resultado.affectedRows === 0) {
            return res.send(`
                <script>
                    alert('Erro: Nenhum usuário encontrado com esse e-mail.');
                    window.location.href = '/deletarUsuario.html';
                </script>
            `);
        }

        res.send(`
            <script>
                alert('Usuário removido com sucesso!');
                window.location.href = '/painel.html';
            </script>
        `);
    });
});

/* EXIBIR TODOS OS USUÁRIOS (EXCLUSIVO ADM) */
/* EXIBIR TODOS OS USUÁRIOS (RETORNO EM JSON) */
/* 1. ROTA QUE ENTREGA A PÁGINA VISUAL (HTML) */
app.get('/usuarios', (req, res) => {
    // Trava de segurança: Verifica se está logado e se é ADM
    if (!req.session.usuario) {
        return res.status(401).send('<h1>Acesso negado. Faça login.</h1>');
    }
    if (req.session.usuario.is_admin !== 1) {
        return res.status(403).send('<h1>Acesso exclusivo para Administradores.</h1>');
    }

    // Envia o arquivo HTML que está dentro da pasta 'public'
    res.sendFile(path.join(__dirname, "public", "usuarios.html"));
});

/* 2. ROTA QUE ENTREGA OS DADOS BRUTOS (JSON) */
app.get('/api/usuarios', (req, res) => {
    if (!req.session.usuario || req.session.usuario.is_admin !== 1) {
        return res.status(403).json({ erro: 'Acesso negado.' });
    }

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    const sql = 'SELECT id, nome, email, is_admin FROM usuarios ORDER BY id ASC ';
    
    conexao.query(sql, (err, resultados) => {
        if (err) {
            return res.status(500).json({ erro: 'Erro no banco de dados.' });
        }
        res.json(resultados); // Esse é o JSON da sua imagem!
    });
});

/* INICIAR SERVIDOR */
app.listen(3000, () => {
    console.log("=================================");
    console.log("Servidor rodando!");
    console.log("http://localhost:3000");
    console.log("=================================");
});