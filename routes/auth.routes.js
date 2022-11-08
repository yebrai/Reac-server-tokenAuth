const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model")
const jwt = require('jsonwebtoken');
const isAuthenticated = require("../middlewares/auth.middlewares")

// aqui iran nuestras rutas de autenticacion

//  POST "/api/auth/singup" => registrar a un usuario (recibiendo email y contraseña)
router.post("/signup", async (req, res , next) => {

    console.log(req.body);
    const {email, password} = req.body

    //1 hacer validaciones backend
    if(!email || !password) {
        res.status(400).json({errorMessage: "Debe tener email y contraseña"})
        return //detiene la ejecucion

    }
    // NO OLVIDAR IMPLEMENTARLO
    // la contraseña sea suficientemente fuerte
    // el email tenga la estructura correcta
    //el usuario no este duplicado


    //2 codificar contraseña

    try {
        
        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(password, salt)

        const newUser = {
            email: email,
            password: hashPassword
        }

        //3 crear el usuario
        await User.create(newUser)

        //si llega aqui esque esta creado el user

    } catch (error) {
        next(error)
    }


    //4 enviar un mensaje de ok al FE

    res.status(201).json("Usuario registrado correctamente")


})

// POST "/api/auth/login" => validar credenciales del usuario
router.post("/login", async (req, res, next) => {

    console.log(req.body)
    const {email, password} = req.body
    
    //1.validaciones backend

    //que todos los campos esten llenos
    if(!email || !password) {
        res.status(400).json({errorMessage: "Debe tener email y contraseña"})
        return //detiene la ejecucion
    }

    try {
       const foundUser = await User.findOne({email: email})
       console.log("usuario:", foundUser);
       if(foundUser === null) {
           res.status(400).json({errorMessage: "Credenciales no validas"})
           return
        }
        
        //que el usuario exista
        //que la contraseña sea correcta
        const isPasswordValid = await bcrypt.compare(password, foundUser.password)
        if (!isPasswordValid) {
            res.status(400).json({errorMessage: "Credenciales no validas"}) // buena practicar
            return
        }
    
        //2. creat algo parecido a la sesión (TOKEN) y enviarlo al cliente

        //payload es la informacion del usuario dueño del token

        const payload = {
            _id: foundUser._id,
            email: foundUser.email
            // si tuviesesmos username o role o otra info del user, tiene que ir aqui
        }

        // a .sign se le pasan 3 argunmentos
        const authToken = jwt.sign(
            payload, // la info del usuario, que sera accesible en diferentes partes de server/cliente
            process.env.TOKEN_SECRET, // palabra SUPER secreta que doble encrypta el token
            {algorithm: "HS256", expiresIn: "6h"} // configuraciones adicionales del Token(Header)
        )

        
        // enviar el token al cliente
        res.status(201).json({authToke: authToken})
    } catch (error) {
        next(error)
    }
})


// get "/api/auth/verify" => para que el BE le diga al FE si el usuario ya ha sido validado
router.get("/verify", isAuthenticated, (req, res, next) => {

    // esta ruta va a verificar que el usuario tiene un Token valido
    // normalmente se ultizara para la primera vez que el usuario visita la web

    // como tenemos acceso a informacion del usuario haciendo esta llamada?
    console.log("req.payload es:",req.payload)
    res.status(200).json("Token valido, usuario ya logeado")

})

module.exports = router;