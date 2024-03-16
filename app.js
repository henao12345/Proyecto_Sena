const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./model/user');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const mongo_uri = 'mongodb+srv://cesarhenaogarcia:Augusto12345@cluster0.3d2eeds.mongodb.net/';

mongoose.connect(mongo_uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log(`Conexión exitosa a ${mongo_uri}`);
})
.catch((error) => {
    console.error('Error al conectar a la base de datos:', error);
});

// Ruta para manejar el registro de usuarios
app.post('/authenticate', async (req, res) => {
    try {
        const { username, email, password, usertype } = req.body;

        // Verificar si el usuario ya existe en la base de datos
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'El usuario ya está registrado' });
        }

        // Cifrar la contraseña antes de guardarla en la base de datos
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear un nuevo usuario con el tipo especificado
        const newUser = new User({ username, email, password: hashedPassword, role: usertype });
        await newUser.save();

        // Enviar respuesta exitosa
        res.status(201).json({ message: 'Usuario registrado correctamente', user: newUser });
    } catch (error) {
        // Manejar errores
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ error: 'Error interno al registrar usuario' });
    }
});

// Ruta para manejar la autenticación de usuarios
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Buscar al usuario en la base de datos por su correo electrónico
        const user = await User.findOne({ email });

        // Si no se encuentra el usuario, responder con un error de autenticación
        if (!user) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        // Verificar la contraseña del usuario
        const isCorrectPassword = await bcrypt.compare(password, user.password);

        // Si la contraseña no es correcta, responder con un error de autenticación
        if (!isCorrectPassword) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        // Si las credenciales son válidas, enviar una respuesta exitosa
        res.status(200).json({ message: 'Inicio de sesión exitoso', user: user });
    } catch (error) {
        // Manejar errores
        console.error('Error al autenticar usuario:', error);
        res.status(500).json({ error: 'Error interno al autenticar usuario' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor iniciado en el puerto ${PORT}`);
});
