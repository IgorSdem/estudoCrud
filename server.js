const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");

const app = express();
const publicDir = path.join(__dirname, "public");

carregarEnv();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    session({
        secret: process.env.SESSION_SECRET || "troque-este-segredo",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 2
        }
    })
);

const conexao = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "123456",
    database: process.env.DB_NAME || "sistema_login"
});

conexao.connect((erro) => {
    if (erro) {
        console.log("Erro ao conectar ao banco:");
        console.log(erro);
        return;
    }

    console.log("Banco conectado com sucesso!");
    prepararBanco();
});

conexao.on("error", (erro) => {
    console.error("Erro na conexao com o banco:", erro.message);
});

function carregarEnv() {
    const envPath = path.join(__dirname, ".env");

    if (!fs.existsSync(envPath)) {
        return;
    }

    const linhas = fs.readFileSync(envPath, "utf8").split(/\r?\n/);

    linhas.forEach((linha) => {
        const conteudo = linha.trim();

        if (!conteudo || conteudo.startsWith("#")) {
            return;
        }

        const separador = conteudo.indexOf("=");

        if (separador === -1) {
            return;
        }

        const chave = conteudo.slice(0, separador).trim();
        const valor = conteudo.slice(separador + 1).trim();

        if (!process.env[chave]) {
            process.env[chave] = valor;
        }
    });
}

function prepararBanco() {
    const sql = "ALTER TABLE usuarios MODIFY senha VARCHAR(255) NOT NULL";

    conexao.query(sql, (erro) => {
        if (erro) {
            console.error("Nao foi possivel ajustar a coluna senha:", erro.message);
            console.error("Execute no MySQL: ALTER TABLE usuarios MODIFY senha VARCHAR(255) NOT NULL;");
            return;
        }

        console.log("Coluna senha preparada para armazenar senhas seguras.");
    });
}

function criarHashSenha(senha) {
    const salt = crypto.randomBytes(16).toString("hex");
    const iterations = 100000;
    const hash = crypto
        .pbkdf2Sync(senha, salt, iterations, 64, "sha512")
        .toString("hex");

    return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function senhaConfere(senha, senhaSalva) {
    if (!senha || !senhaSalva) {
        return false;
    }

    const partes = senhaSalva.split("$");

    if (partes.length !== 4 || partes[0] !== "pbkdf2") {
        return senha === senhaSalva;
    }

    const iterations = Number(partes[1]);
    const salt = partes[2];
    const hashSalvo = partes[3];
    const hashInformado = crypto
        .pbkdf2Sync(senha, salt, iterations, 64, "sha512")
        .toString("hex");
    const bufferSalvo = Buffer.from(hashSalvo, "hex");
    const bufferInformado = Buffer.from(hashInformado, "hex");

    if (bufferSalvo.length !== bufferInformado.length) {
        return false;
    }

    return crypto.timingSafeEqual(bufferSalvo, bufferInformado);
}

function senhaPrecisaMigrar(senhaSalva) {
    return !String(senhaSalva || "").startsWith("pbkdf2$");
}

function usuarioSessao(usuario) {
    return {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        is_admin: Number(usuario.is_admin)
    };
}

function validarId(req, res, next) {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ erro: "ID invalido." });
    }

    req.params.id = id;
    next();
}

function exigirLogin(req, res, next) {
    if (!req.session.usuario) {
        return res.redirect("/");
    }

    next();
}

function exigirAdmin(req, res, next) {
    if (!req.session.usuario) {
        return res.status(401).send("<h1>Acesso negado. Faca login.</h1>");
    }

    if (Number(req.session.usuario.is_admin) !== 1) {
        return res.status(403).send("<h1>Acesso exclusivo para administradores.</h1>");
    }

    next();
}

function validarUsuario({ nome, email, senha }, senhaObrigatoria = true) {
    if (!nome || nome.trim().length < 3) {
        return "Informe um nome com pelo menos 3 caracteres.";
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return "Informe um e-mail valido.";
    }

    if (senhaObrigatoria && (!senha || senha.length < 6)) {
        return "Informe uma senha com pelo menos 6 caracteres.";
    }

    if (!senhaObrigatoria && senha && senha.length < 6) {
        return "A nova senha precisa ter pelo menos 6 caracteres.";
    }

    return null;
}

app.get("/", (req, res) => {
    res.sendFile(path.join(publicDir, "login.html"));
});

app.get("/painel.html", exigirLogin, (req, res) => {
    res.sendFile(path.join(publicDir, "painel.html"));
});

app.get("/dashboard", exigirLogin, (req, res) => {
    res.sendFile(path.join(publicDir, "dashboard.html"));
});

app.get("/dashboard.html", exigirLogin, (req, res) => {
    res.sendFile(path.join(publicDir, "dashboard.html"));
});

app.get("/cadastroUsuario.html", exigirAdmin, (req, res) => {
    res.sendFile(path.join(publicDir, "cadastroUsuario.html"));
});

app.get("/deletarUsuario.html", exigirAdmin, (req, res) => {
    res.sendFile(path.join(publicDir, "deletarUsuario.html"));
});

app.get("/atualizarUsuario.html", exigirAdmin, (req, res) => {
    res.sendFile(path.join(publicDir, "atualizarUsuario.html"));
});

app.get("/usuarios", exigirAdmin, (req, res) => {
    res.sendFile(path.join(publicDir, "usuarios.html"));
});

app.post("/login", (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).send("Informe e-mail e senha.");
    }

    const sql = "SELECT id, nome, email, senha, is_admin FROM usuarios WHERE email = ?";

    conexao.query(sql, [email], (erro, resultado) => {
        if (erro) {
            console.log("Erro SQL:", erro);
            return res.status(500).send("Erro ao consultar banco.");
        }

        if (resultado.length === 0 || !senhaConfere(senha, resultado[0].senha)) {
            return res.status(401).send("Usuario ou senha invalidos.");
        }

        const usuario = resultado[0];
        req.session.usuario = usuarioSessao(usuario);

        if (senhaPrecisaMigrar(usuario.senha)) {
            conexao.query(
                "UPDATE usuarios SET senha = ? WHERE id = ?",
                [criarHashSenha(senha), usuario.id],
                (erroMigracao) => {
                    if (erroMigracao) {
                        console.error("Nao foi possivel migrar a senha para hash:", erroMigracao.message);
                    }
                }
            );
        }

        return res.redirect("/painel.html");
    });
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.post("/cadastrar", exigirAdmin, (req, res) => {
    const { nome, email, senha, confirmarSenha } = req.body;

    if (senha !== confirmarSenha) {
        return res.status(400).send("<h1>Erro: as senhas nao coincidem.</h1>");
    }

    const erroValidacao = validarUsuario({ nome, email, senha });

    if (erroValidacao) {
        return res.status(400).send(`<h1>${erroValidacao}</h1>`);
    }

    const sql = "INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)";

    conexao.query(sql, [nome.trim(), email.trim(), criarHashSenha(senha)], (err) => {
        if (err) {
            console.error("Erro ao inserir no banco de dados:", err);

            if (err.code === "ER_DUP_ENTRY") {
                return res
                    .status(409)
                    .send('<h1>Erro: este e-mail ja esta cadastrado.</h1><a href="/cadastroUsuario.html">Tentar novamente</a>');
            }

            return res.status(500).send("<h1>Erro interno ao salvar o usuario.</h1>");
        }

        res.send(`
            <script>
                alert('Usuario cadastrado com sucesso!');
                window.location.href = '/usuarios';
            </script>
        `);
    });
});

app.post("/atualizar/:id", exigirAdmin, validarId, (req, res) => {
    const { id } = req.params;
    const { novoNome, email, novaSenha } = req.body;
    const erroValidacao = validarUsuario(
        { nome: novoNome, email, senha: novaSenha },
        false
    );

    if (erroValidacao) {
        return res.status(400).send(erroValidacao);
    }

    const campos = ["nome = ?", "email = ?"];
    const valores = [novoNome.trim(), email.trim()];

    if (novaSenha) {
        campos.push("senha = ?");
        valores.push(criarHashSenha(novaSenha));
    }

    valores.push(id);

    const sql = `UPDATE usuarios SET ${campos.join(", ")} WHERE id = ?`;

    conexao.query(sql, valores, (err, resultado) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Erro ao atualizar usuario.");
        }

        if (resultado.affectedRows === 0) {
            return res.status(404).send("Usuario nao encontrado.");
        }

        res.send(`
            <script>
                alert('Usuario atualizado com sucesso!');
                window.location.href = '/usuarios';
            </script>
        `);
    });
});

app.post("/deletar", exigirAdmin, (req, res) => {
    const { emailDeletar } = req.body;

    if (!emailDeletar) {
        return res.status(400).send("<h1>Informe o e-mail do usuario.</h1>");
    }

    conexao.query(
        "DELETE FROM usuarios WHERE email = ?",
        [emailDeletar.trim()],
        (err, resultado) => {
            if (err) {
                console.error("Erro ao deletar no banco de dados:", err);
                return res.status(500).send("<h1>Erro interno ao deletar o usuario.</h1>");
            }

            if (resultado.affectedRows === 0) {
                return res.send(`
                    <script>
                        alert('Erro: nenhum usuario encontrado com esse e-mail.');
                        window.location.href = '/deletarUsuario.html';
                    </script>
                `);
            }

            res.send(`
                <script>
                    alert('Usuario removido com sucesso!');
                    window.location.href = '/usuarios';
                </script>
            `);
        }
    );
});

app.get("/api/usuarios", exigirAdmin, (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");

    conexao.query(
        "SELECT id, nome, email, is_admin FROM usuarios ORDER BY id ASC",
        (err, resultados) => {
            if (err) {
                return res.status(500).json({ erro: "Erro no banco de dados." });
            }

            res.json(resultados);
        }
    );
});

app.get("/api/usuarios/:id", exigirAdmin, validarId, (req, res) => {
    conexao.query(
        "SELECT id, nome, email, is_admin FROM usuarios WHERE id = ?",
        [req.params.id],
        (err, resultado) => {
            if (err) {
                return res.status(500).json({ erro: "Erro no banco de dados." });
            }

            if (resultado.length === 0) {
                return res.status(404).json({ erro: "Usuario nao encontrado." });
            }

            res.json(resultado[0]);
        }
    );
});

app.delete("/api/usuarios/:id", exigirAdmin, validarId, (req, res) => {
    if (Number(req.session.usuario.id) === Number(req.params.id)) {
        return res.status(400).json({ erro: "Voce nao pode excluir seu proprio usuario." });
    }

    conexao.query("DELETE FROM usuarios WHERE id = ?", [req.params.id], (err, resultado) => {
        if (err) {
            return res.status(500).json({ erro: "Erro no banco de dados." });
        }

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ erro: "Usuario nao encontrado." });
        }

        res.json({ sucesso: true });
    });
});

app.use((req, res, next) => {
    if (req.path.endsWith(".html")) {
        return res.redirect("/");
    }

    next();
});

app.use(express.static(publicDir, { index: false }));

app.listen(process.env.PORT || 3000, () => {
    const porta = process.env.PORT || 3000;

    console.log("=================================");
    console.log("Servidor rodando!");
    console.log(`http://localhost:${porta}`);
    console.log("=================================");
});
