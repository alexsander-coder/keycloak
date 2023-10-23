import express from 'express';
import crypto from 'crypto';
import session from 'express-session';
import jwt from 'jsonwebtoken';

const app = express();

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
}

app.get('/login', (req, res) => {

    //prevent replay attack
    const nonce = crypto.randomBytes(16).toString("base64");

    console.log(nonce, 'details of nonce')
    // @ts-expect-error - type mismatch
    req.session.nonce = nonce;

    req.session.save();


    console.log(nonce, 'details depois do save de nonce ')

    // /login  ----> keycloak (form de auth) ----> callback com o codigo de auth ----> keycloak devolve o token.
    //
    const loginParams = new URLSearchParams({
        client_id: 'fullcycle-client',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'openid',
        nonce
    });

    const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/auth?${loginParams.toString()}`
    console.log(url);
    res.redirect(url);
});

app.get('/callback', async (req, res) => {
    console.log(req.query);

    //gerar o nonse
    const bodyParams = new URLSearchParams({
        client_id: 'fullcycle-client',
        grant_type: 'authorization_code',
        code: req.query.code as string,
        redirect_uri: 'http://localhost:3000/callback'
    })
    //172.0.0.1 host.docker.internal
    const url = `http://host.docker.internal:8080/realms/fullcycle-realm/protocol/openid-connect/token`;

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: bodyParams.toString(),
    });

    const result = await response.json();

    console.log(result)

    const payloadAccessToken = jwt.decode(result.access_token) as any;
    console.log(payloadAccessToken)

    const payloadRefreshToken = jwt.decode(result.refresh_token) as any;
    const payloadIdToken = jwt.decode(result.id_token) as any;

    if (
        //@ts-expect-error - type mismatch
        payloadAccessToken.nonce !== req.session.nonce ||
        //@ts-expect-error - type mismatch
        payloadRefreshToken.nonce !== req.session.nonce ||
        //@ts-expect-error - type mismatch
        payloadIdToken.nonce !== req.session.nonce) {

        return res.status(401).json({ message: 'Unauthenticated' })
    }
    console.log(payloadAccessToken);

    // @ts-expect-error - type mismatch
    req.session_user = payloadAccessToken;

    // @ts-expect-error - type mismatch
    req.session.access_token = result.access_token;

    // @ts-expect-error - type mismatch
    req.session.id_token = result.id_token;

    req.session.save();

    res.json(result);
})

app.get("/admin", middlewareIsAuth, (req, res) => {
    // @ts-expect-error - type mismatch
    res.json(req.session.user);
})

app.listen(3000, () => {
    console.log('Listering on port 3000');
})