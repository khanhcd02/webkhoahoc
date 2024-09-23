const jwt = require('jsonwebtoken')
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const verifyToken = (req,res,next) => {
    const token = req.cookies.accessToken

    if(!token) return res.sendStatus(401)

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        req.userId = decoded.userId
        next()
    } catch (error) {
        console.log(error)
        return res.sendStatus(403)
    }
}

module.exports = verifyToken