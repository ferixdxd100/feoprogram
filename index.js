const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')

// config
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'jefry_kill_jews'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'


//cookie bealitas

const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,//7nap
}
//adatbazis bealitas
const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'szavazas'
})

//APP
const app = express();
app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: '*',
    credentials: true
}))
function auth(req, res, next){
    const token=req.cookies[COOKIE_NAME];
    if(!token){
        return res.status(409).json({message:"nincs bejelenkezés"})
    }
    try{
        req.user=jwt.verify(token, JWT_SECRET)
        next();
    }catch(error){
        return res.status(410).json({message:"nem ervenys token"})
    }
}

//végpontotk

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;

    // bemeneti adatok ellenorzese
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json({ message: "hianyzó bemeneti adaatok" })
    }

    //ellenörzes a felonevet es az emailt hogy egydi e
    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem valos email cim" })
        }
        const emailFelhasznaloSQL = 'SELECT * FROM felhasznalok WHERE email=? OR felhasznalonev=?'
        const [exists] = await db.query(emailFelhasznaloSQL, [email, felhasznalonev]);
        if (exists.length) {
            return res.status(402).json({ message: "az email vag  a felhasznalo nev foglalt" })
        }
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracio = 'INSERT INTO felhasznalok(email, felhasznalonev, jelszo,admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracio, [email, felhasznalonev, hash, admin]);

        return res.status(200).json({
            message: "sikeres regisztrácio",
            id: result.insertId
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasznaloVagyEmail, jelszo } = req.body;
    if (!felhasznaloVagyEmail || !jelszo) {
        return res.status(400).json({ message: "hinyos belépesi adatok" })
    }
    try {
        const isValid = await emailValidator(felhasznaloVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            const sql = 'SELECT * FROM felhasznalok WHERE email=?'
            const [rows] = await db.query(sql, [felhasznaloVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "ezzel a felhasznao nevel nem regisztráltak" })
            }

        } else {
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev =?'
            const [rows] = await db.query(sql, [felhasznaloVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "ezzel a felhasznalonevel még nem regisztráltak" })
            }
        }

        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(403).json({ message: "Rosz jelszot adot meg" })
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        )


        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({ message: "sikeres belepés" })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "szerverhiba" })
    }
})

app.post('/kiselentkezes',auth, async(req, res)=>{
    res.clearCookie(COOKIE_NAME,{path:'/'});
    res.status(200).json({message:"sikeres kijelenkezes"})
})

app.get('/adataim' ,auth, async (req, res)=>{
    res.status(200).json(req.user)
})

app.put('/email', auth, async(req, res) =>{
    const {ujEmail}=req.body;
    if (!ujEmail){
        res.status(401).json({message:"az uj email megadasa koteloze"})
    }
    const isValid = await emailValidator(ujEmail)
    if(!isValid) {
        return res.status(402).json({message:"az email formatum nem mefelelö"})
    }
    try{
        const sql1 ='SELECT * FROM felhasznalok WHERE email=?'
        const [result] = await db.query(sql1, [ujEmail])
        if(result.length){
            return res.status(403).json({message:"az email cim mar foglalt"})
        }

        const sql2 ='UPDATE felhasznalok SET email = ? WHERE id =?'
        const [update] = await db.query(sql2,[ujEmail,req.user.id]);
        return res.status(200).json({message:"sikeresen modosult az email"})
    }catch(error){
        console.log(error);
        res.status(500).json({message:"szerverhiba"})
    }
})


app.put('/felhasznalonev', auth, async(req, res) =>{
    const {ujFelhasznalonev}=req.body;
    if (!ujFelhasznalonev){
        res.status(401).json({message:"az uj felhasznalonev megadasa koteloze"})
    }
    try{
        const sql1 ='SELECT * FROM felhasznalok WHERE felhasznalonev=?'
        const [result] = await db.query(sql1, [ujFelhasznalonev])
        if(result.length){
            return res.status(403).json({message:"az felhasznalonev cim mar foglalt"})
        }

        const sql2 ='UPDATE felhasznalok SET felhasznalonev = ? WHERE id =?'
        const [update] = await db.query(sql2,[ujFelhasznalonev,req.user.id]);
        return res.status(200).json({message:"sikeresen modosult az felhasznalonev"})
    }catch(error){
        console.log(error);
        res.status(500).json({message:"szerverhiba"})
    }
})

app.put('/jelszo', auth, async(req, res) =>{
    const {regiJelszo, ujJelszo}=req.body;
    if (!regiJelszo || !ujJelszo){
        return res.status(401).json({message:"a regi es az uj jelszo megadasa kotelezo"})
    }
    try{
        const sql1 ='SELECT jelszo FROM felhasznalok WHERE id=?'
        const [result] = await db.query(sql1, [req.user.id])
        if(!result.length){
            return res.status(404).json({message:"felhasznalo nem talalhato"})
        }

        const ok = await bcrypt.compare(regiJelszo, result[0].jelszo)
        if(!ok){
            return res.status(403).json({message:"a regi jelszo nem helyes"})
        }

        const hash = await bcrypt.hash(ujJelszo, 10);
        const sql2 ='UPDATE felhasznalok SET jelszo = ? WHERE id =?'
        await db.query(sql2,[hash, req.user.id]);
        return res.status(200).json({message:"sikeresen modosult a jelszo"})
    }catch(error){
        console.log(error);
        res.status(500).json({message:"szerverhiba"})
    }
})
 app.delete('/fiokom', auth,async(req,res)=>{
    const userid=  [req.user.id];
    try {
        const sql ='DELETE FROM felhasznalok WHERE id=?';
        await db.query(sql,userid);
        res.clearCookie(COOKIE_NAME,{path:'/'});
        res.status(200).json({message:"sikeres fioktorles"})
    } catch (error) {
        console.log(error);
        res.status(500).json({messege:"szerverhiba"})
    }
 })

//szerver inditas
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`);
})