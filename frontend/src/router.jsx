import React from "react";
import { SignIn,SignUp,ChooseSignUpOrSignIn } from "./Components/Signup";
import { createBrowserRouter } from "react-router-dom";
import App from "./App";
import Play from "./Components/Play";
export const router = createBrowserRouter([
    {
        path: '/',
        element: <App/>,
        children:[
            {
                index:true,
                element:<ChooseSignUpOrSignIn/>
            },
            {
                path: '/signup',
                element:<SignUp/>
            },
            {
                path:'/signin',
                element:<SignIn/>
            },
            {
                path:'/play',
                element: <Play/>
            }
        ]
        
    }
   
])