const express = require('express')
const cors = require('cors')
const cookieParser= require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator= require('node-email-verifier')

// config
const PORT =3000;
const HOST ='localhost'
const JWT_SECRET='jefry_kill_jews'
const JWT_EXPIRES_IN='7d'
const COOKIE_NAME='auth_token'


//cookie bealitas

const COOKIE_OPTS={
    httpOnly: true,
    secure: false,
    sameSite:'lax',
    path:'/',
    maxAge: 7 * 24 * 60 * 60 * 1000,//7nap
}
//adatbazis bealitas
const db= mysql.createPool({
    host:'localhost',
    port: '3306',
    user: 'root',
    password:'',
    database:'szavazas'
})

//APP
const app =express();
app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin:'*',
    credentials:true
}))

//végpontotk

app.post('/regisztracio', async (req, res)=>{
    const {email, felhasznalonev, jelszo, admin}=req.body;

    // bemeneti adatok ellenorzese
    if(!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json({message: "hianyzó bemeneti adaatok"})
    }

    //ellenörzes a felonevet es az emailt hogy egydi e
    try{
        const isValid = await emailValidator(email)
        if(!isValid){
            return res.status(401).json({message:"nem valos email cim"})
        }
        const emailFelhasznaloSQL='SELECT * FROM felhasznalok WHERE email=? OR felhasznalonev=?'
        const [exists]= await db.query(emailFelhasznaloSQL, [email, felhasznalonev]);
        if (exists.length){
            return res.status(402).json({message:"az email vag  a felhasznalo nev foglalt"})
        }
        const hash= await bcrypt.hash(jelszo,10);
        const regisztracio = 'INSERT INTO felhasznalok(id, email, felhasznalonev, jelszo,admin) VALUES (?,?,?,?)'
        const result =await db.query(regisztracioSQL, [email,felhasznalonev, hash, admin]);
        
        return res.status(200).json({
            message:"sikeres regisztrácio",
            id: result.insertId
        })
    }catch(error) {
        console.log(error);
        return res.status(500).json({message:"Szerverhiba"})
    }
})

app.post('/belepes' ,async (req, res)=>{
    const {felhasznaloVagyEmail, jelszo}=req.body;
    if(!felhasznaloVagyEmail|| !jelszo){
        return res.status(400).json({message: "hinyos belépesi adatok"})
    }
   try{
    const isValid = await emailValidator(felhasznaloVagyEmail)
    let hashJelszo="";
    let user = {}
    if (isValid) {
        const sql ='SELECT * FROM felhasznalok WHERE email=?'
        const [rows]= await db.query(sql,[felhasznaloVagyEmail]);
        if(rows.length){
            user =rows[0];
            hashJelszo=user.jelszo;
        }else{
            return res.status(401).json({message:"ezzel a felhasznao nevel nem regisztráltak"})
        }
        
    }else{
        const sql ='SELECT * FROM felhasznalok WHERE felhasznalonev =?'
        const [rows]= await db.query(sql,[felhasznaloVagyEmail]);
        if (rows.length) {
            user=rows[0];
            hashJelszo=user.jelszo;
        }else{
            return res.status(401).json({message:"ezzel a felhasznalonevel még nem regisztráltak"})
        }
    }

    const ok = bcrypt.compare(jelszo,hashJelszo )

   if(ok){
        const token = jwt.sign(
            {id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin},
            JWT_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )
   }
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message:"sikeres belepés"})
   }catch(error){
    console.log(error)
    return res.status(500).json({message:"szerverhiba"})
   }
})

app.post('/adataim' ,auth, async (req, res)=>{
    
})

//szerver inditas
app.listen(PORT,HOST, ()=>{
    console.log(`API fut: http://${HOST}:${PORT}/`);
})