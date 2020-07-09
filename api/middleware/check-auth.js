const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    try {
       const token = req.headers.authorization.split(" ")[1];
       // console.log(token);
       // getting toke as from header and rejecting the Bearer part before space using split
       const decoded = jwt.verify(token, process.env.JWT_KEY);
       req.userData = decoded;
       next();
    }
    catch (error) {
       return res.status(401).json({
           message: 'Auth failed'
       });
    }
    
};