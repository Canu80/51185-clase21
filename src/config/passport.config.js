import passport from 'passport';
import local from 'passport-local';
import GitHubStrategy from 'passport-github2';

import userModel from '../models/User.model.js';
import {createHash, validatePassword } from '../utils.js';

const LocalStrategy = local.Strategy;

const initializePassport = () => {
    
    passport.serializeUser((user,done)=>{
        done(null, user._id)
    });
    
    passport.deserializeUser( async (id , done)=>{
        let user = await userModel.findById(id);
        done(null, user)
    });

    passport.use('register', new LocalStrategy({ passReqToCallback:true, usernameField:'email'}, async (req,username,password,done) =>{
            const {first_name, last_name, email, age } = req.body;
            try {
                let user = await userModel.findOne({email:username});
                if(user){
                    console.log('El usuario existe');
                    return done(null,false);
                }
                const newUser = {
                        first_name,
                        last_name,
                        email,
                        age,
                        password: createHash(password)
                }
                let result = await userModel.create(newUser);
                return done(null, result);
            } catch (error) {
                return done("Error al obtener el usuario: " + error)
            }
        }
    ));

    passport.use('login', new LocalStrategy({usernameField:'email'}, async (username, password, done)=>{
        try {
           const user = await userModel.findOne({email:username})
           if(!user){
                console.log('No existe el usuario');
                return done(null, false);
            }
            if(!validatePassword(password,user)) return done (null, false);
            return done(null,user);
        } catch (error) {
            return done("Error al intentar ingresar: " + error);            
        }
    }));


    passport.use('github', new GitHubStrategy({
        clientID:'Iv1.a5fdc5466f50deaa',
        clientSecret:'bd5693a08967bf53c86fba661ab5df6adebb5888',
        callbackURL: 'http://localhost:8080/api/sessions/githubcallback'
    }, async (accesToken, refreshToken,profile,done)=>{
        try {
            let user = await userModel.findOne({email: profile._json.email})
            console.log(profile);
            
            if(!user){
                const email = profile._json.email == null ?  profile._json.username : null;
                const newUser = {
                        first_name: profile._json.name,
                        typeUser: "GitHub",
                        password: "",
                }
                const result = await userModel.create(newUser);
                done(null,result)
            }else{
                done(null, user)
            }
        } catch (error) {
            return done(null,error)
        }
    }))
}
export default initializePassport;
