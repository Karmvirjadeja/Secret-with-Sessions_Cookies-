import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import env from "dotenv";
env.config()

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//Creating the session middle wares
app.use(session({
  secret:process.env.SESSIOIN_SECRET,
  resave:false, //false as we dont want to save the data into the postges data base 
  saveUninitialized:true,
  cookie:{
    maxAge:1000*60*60*24,
  }
})
);


//Creating passport middle wares and must be afrer the session middlewares
app.use(passport.initialize());
app.use(passport.session());







const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database:process.env.DATABASE_NAME,
  password:process.env.DATABASE_PASS,
  port: 5432,
});
db.connect();



app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});                                                                                                                   

app.get("/register", (req, res) => {
  res.render("register.ejs");
});


app.get("/secrets",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }
  else{
    res.render("/login");
  }
});



app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});




app.post("/login", 
passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
})
);



app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});




passport.use(new Strategy(async function verify(username,password,cb){

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);




    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;



      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } else {
          if (valid) {
         return   cb(null,user);
          } else {
          return  cb(null,false);
          }
        }
      });


    } 
    
    
    
    else {
      return cb("User not found");
    }
  }
  
  
  catch (err) {
    console.log(err);
  }


}));

// Converting the user in to the cookie format.
passport.serializeUser((user,cb)=>{
  cb(null,user);
});


//Converting the cookie format previously into the cookie format 
passport.deserializeUser((user,cb)=>{
  cb(null,user);
});







app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


/*
function cb(err, user, info) {
  // ...
}


*/