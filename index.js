const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const dotenv = require('dotenv')
dotenv.config()
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// Authentication
const isLoggedIn = (req, res, next) => {
    try {
        const jwtToken = req.headers.token
        let userDetails = jwt.verify(jwtToken, process.env.JWT_PRIVATE_KEY)
        if(!userDetails)
            throw new Error()
        req.user = userDetails
        next()
    } catch (error) {
        return res.json({
            message: "You're not logged in! Please login"
        })
    }
}

// Authorization
const isAdmin = (req, res, next) => {
    if(!req.user.isAdmin)
        return res.json({
            message: "You don't have access to this page!"
        })
    next()
}

const isPremium = (req, res, next) => {
    if(!req.user.isPremium)
        return res.json({
            message: "You don't have access to this page!"
        })
    next()
}

app.use(cors())
app.use(bodyParser.urlencoded())
app.use(bodyParser.json())

const User = mongoose.model('User', { // users
    fullName: String,
    email: String,
    password: String,
    isAdmin: Boolean,
    isPremium: Boolean
})

app.get('/', (req, res) => {
    res.send('Our first Node Express Server!')
})

app.get('/users', async (req, res) => {
    try {
        const users = await User.find()
        res.json({
            status: 'SUCCESS',
            data: users
        })
    } catch (error) {
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})

app.post('/signup', async (req, res) => {
    const { fullName, email, password, isAdmin, isPremium } = req.body
    try {
        const user = await User.findOne({ email })
        if(user) {
            return res.json({
                status: "User with this email exists. Please login"
            })
        }

        const encryptedPassword = await bcrypt.hash(password, 10)
        await User.create({ 
            fullName, 
            email, 
            password: encryptedPassword, 
            isAdmin, 
            isPremium 
        })
        res.json({
            status: 'SUCCESS'
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})

app.post('/login', async (req, res) => {
    const { email, password } = req.body
    try {
        const user = await User.findOne({ email })
        if(!user) {
            return res.json({
                status: "User with this email doesn't exist. Please signup"
            })
        }

        const passwordMatches = await bcrypt.compare(password, user.password)
        if(!passwordMatches)
            return res.json({
                status: 'Incorrect credentials!'
            })

        const jwToken = jwt.sign(user.toJSON(), process.env.JWT_PRIVATE_KEY, { expiresIn: 30 })

        return res.json({
            status: 'Login successful!',
            jwToken
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})

// Private Routes: Accessible only if User is Authenticated/Authorized
app.get('/profile', isLoggedIn, async (req, res) => {
    try {
        res.json({
            status: 'PROFILE PAGE'
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})

app.get('/admin/dashboard', isLoggedIn, isAdmin, async (req, res) => {
    try {
        res.json({
            status: 'ADMIN DASHBOARD PAGE'
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})

app.get('/premium', isLoggedIn, isPremium, async (req, res) => {
    try {
        res.json({
            status: 'PREMIUM PAGE'
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({
            status: 'FAILED',
            message: 'Something went wrong!'
        })
    }
})


app.listen(process.env.PORT, () => {
    mongoose
        .connect(process.env.MONGODB_URL)
        .then(() => console.log('Server is up :)'))
        .catch((error) => console.log(error))
})

/*
    Login/Signup

    Authentication: 
        - Who are you? 
        - Checking whether the user is having an account
    Authorization:
        - What access do you have?
        - Checking what access the user has

    Encryption:
        - Encrypt: Original Password -> Encrypted Password
        - Decrypt: Encrypted Password -> Original Password

    - bcrypt
    - jsonwebtoken
*/