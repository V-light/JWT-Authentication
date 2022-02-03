const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');

app.use(express.json());
const users = [
    { 
        id: "1",
        username: "suraj1",
        password: "suraj123",
        isAdmin : true
    },
    { 
        id: "2",
        username: "suraj2",
        password: "suraj123",
        isAdmin : false
    }
];
let refreshTokens = [];
const generateAccessToken = (user)=>{
    return jwt.sign({id:user.id, isAdmin: user.isAdmin}, "mysecretkey", {expiresIn: "5m"})
}

const generateRefreshToken = (user)=>{
    return jwt.sign({id:user.id, isAdmin: user.isAdmin}, "myrefreshsecretkey", {expiresIn: "5m"})
}

app.post('/api/login', (req, res)=>{
    const {username, password} = req.body;

    const user = users.find(u=>{
        return u.username ===username && u.password===password;
    })

    const accesstoken = generateAccessToken (user);
    const refreshtoken = generateRefreshToken (user);

    refreshTokens.push(refreshtoken);

    if(user){
        res.json({
            username : user.username,
            isAdmin: user.isAdmin,
            accesstoken,
            refreshtoken
        });
    }else{
        res.send("Invalid Data");
    }
})

app.post('/api/refresh', (req, res) => {
    const refreshToken = req.body.refreshtoken;
    if(!refreshToken){
        return res.status(401).send('you are not authorized');

    }
    if(!refreshTokens.includes(refreshToken)){
        return res.status(401).json("Invalid Token");
    }
    
    jwt.verify(refreshToken, "myrefreshsecretkey" , (err, user) => {
        err&&console.log(err);

        refreshTokens = refreshTokens.filter(token=> token!==refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            newAccessToken,
            newRefreshToken
        })
    })
})

const verify = (req, res, next) =>{
    const authHeader = req.headers.authorization;

    if(authHeader){
        const token = authHeader.split(" ")[1];

        jwt.verify(token, "mysecretkey", (err, user) => {
            if(err){
                return  res.status(500).send("invalid token");
            }
            req.user = user;
            next();
        })
    }else{
        res.status(404).json("you are not authorized");
    }


}
app.delete('/api/user/:userId', verify, (req, res)=>{
    if(req.user.id === req.params.userId|| req.user.isAdmin){
        res.status(200).send("account has been deleted");
    }else{
        res.status(404).send("you are not allowed to delete this account");
    }
})

app.post('/api/logout', verify, (req, res) =>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token!==refreshToken);

    res.status(200).send("you are logged out successfully");
})
app.listen(3000, ()=>{
    console.log('Backend Server is Running');
})