import express from 'express';
import session from 'express-session';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const memoryStore = new session.MemoryStore()

app.use(session({
    secret: 'my-secret',
    resave: false,
    saveUninitialized: false,
    store: memoryStore
}));

const middlewareIsAuth = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) => {

    // @ts-expect-error - type mismatch
    if (!req.session.user) {
        return res.redirect("/login")
    }
    next();
}

app.get('/login', (req, res) => {
    res.sendFile(__dirname + "/login.html");
});

app.post('/login', async (req, res) => {

    const { username, password } = req.body;

    const response = await fetch('http://host.docker.internal:8080/realms/fullcycle-realm/protocol/openid-connect/token', {
        method: 'POST',
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
            client_id: "fullcycle-client",
            grant_type: "password",
            username,
            password,
            scope: 'openid',


        }).toString(),
    })

    const result = await response.json();
    console.log(result);
    //@ts-expect-error - type mismatch
    req.session.user = result;
    req.session.save();

    // res.redirect("/admin")
    res.send(result)
})


app.get("/logout", async (req, res) => {
    // const logoutParams = new URLSearchParams({
    //     // @ts-expect-error - type mismatch
    //     id_token_hint: req.session.user.id_token,
    //     post_logout_redirect_uri: "http://localhost:3000/login",
    // });

    // req.session.destroy((err) => {
    //     if (err) {
    //         console.error(err);
    //     }
    // });

    // const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/logout?${logoutParams.toString()}`

    await fetch('http://host.docker.internal:8080/realms/fullcycle-realm/protocol/openid_connect/revoke', {
        method: 'POST',
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
            client_id: "fullcycle-client",
            //@ts-expect-error
            token: req.session.user.refresh_token,
        }).toString(),
    });

    //verify response.ok
    req.session.destroy((err) => {
        console.error(err);
    });

    res.redirect("/login");
});


app.get('/callback', async (req, res) => {

    // @ts-expect-error - type mismatch
    if (req.session.user) {
        return res.redirect("/admin");
    }

    //@ts-expect-error - type mismatch
    if (req.query.state !== req.session.state) {
        res.status(401).json({ message: "Unauthenticated" })
    }


    const bodyParams = new URLSearchParams({
        client_id: 'fullcycle-client',
        grant_type: 'authorization_code',
        code: req.query.code as string,
        redirect_uri: 'http://localhost:3000/callback',
    });

    const url = `http://host.docker.internal:8080/realms/fullcycle-realm/protocol/openid_connect/token`;

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: bodyParams.toString()
    });


    const result = await response.json();


    const payloadAccessToken = jwt.decode(result.access_token) as any;
    const payloadRefreshToken = jwt.decode(result.refresh_token) as any;
    const payloadIdToken = jwt.decode(result.id_token) as any;

    if (
        //@ts-expect-error - type mismatch
        payloadAccessToken!.nonce !== req.session.nonce ||
        //@ts-expect-error - type mismatch
        payloadRefreshToken.nonce !== req.session.nonce ||
        //@ts-expect-error - type mismatch
        payloadIdToken.nonce !== req.session.nonce) {

        return res.status(401).json({ message: 'Unauthenticated' })
    }

    // @ts-expect-error - type mismatch
    req.session_user = payloadAccessToken;

    // @ts-expect-error - type mismatch
    req.session.access_token = result.access_token;

    // @ts-expect-error - type mismatch
    req.session.id_token = result.id_token;

    req.session.save();

    console.log('entrou no index.ts em seguida o json')

    // res.json(result);
    res.redirect("/admin");
})


app.get("/admin", middlewareIsAuth, (req, res) => {

    //// @ts-expect-error - type mismatch
    // res.json(req.session.user);
    res.send('Admin carai de asa')
})

app.listen(3000, () => {
    console.log('Listering on port 3000');
})
