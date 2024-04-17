import React from "react";
import Button from "react-bootstrap/Button";
import {useNavigate} from 'react-router-dom';
import Form from 'react-bootstrap/Form';
import { api } from "../utilities";
import { useState } from "react";

export function ChooseSignUpOrSignIn(){
    const navigate = useNavigate()
    console.log('in choose')
   return (
    <>
    <div className="text-center home-background h-screen">
    <p className="home-header">Welcome to Adventue Game</p>
    <div className="flex justify-around">
        <Button onClick={()=>navigate('/signup')} variant="primary">Click here for SignUp</Button>
        <Button onClick = {()=>navigate('/signin')}variant="primary">Click here for SignIn</Button>
    </div>
    </div>
    
    </>)
}
export function SignUp(){
    const navigate = useNavigate()
    const [username,setUsername] = useState('')
    const [password,setPassword] = useState('')
    const [showError, setShowError] = useState(false)
    const handleSubmit = async (event)=>{
        event.preventDefault();
       let data = {
            'username':username,
            'password':password 
        }
        console.log(data)
        try{
            let response = await api.post('users/signup/',data)
        
            const {token}= response.data
            console.log(token)
           localStorage.setItem('token',token)
        //    for all future requests
            api.defaults.headers.common['Authorization'] = `Token ${token}`
            navigate('/play')
            console.log('we are through!!')
        
        }
        catch(error){
            console.log(error)
            setShowError(true)
            setTimeout(()=>{
                setShowError(false)
            },3000)
        }
    }
    
    return (
        <>
        <div className="signup-background h-screen">
        <h1 className="text-center">Sign up</h1>
        <div className="text-center flex justify-center">
            
                <Form>
                    <Form.Group className="mb-3" controlId="formBasicUsername">
            <Form.Label>Username</Form.Label>
            <Form.Control onChange={(e)=>setUsername(e.target.value)} type="username" placeholder="Enter username" />
            <Form.Text className="text-muted">
                We'll never share your username with anyone else.
            </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3" controlId="formBasicPassword">
            <Form.Label>Password</Form.Label>
            <Form.Control onChange={(e)=>setPassword(e.target.value)} type="password" placeholder="Password" />
            </Form.Group>
            <Button onClick={handleSubmit} variant="primary" type="submit">
            Submit
            </Button>
        </Form>
        </div>
        {
            showError &&
            <p className="text-center text-red-500 font-bold">User already exists!</p>
        }
        </div>
        </>
    )
}

export function SignIn(){
    const navigate = useNavigate()
    const [username,setUsername] = useState('')
    const [password,setPassword] = useState('')
    const [showError,setShowError] = useState(false)

    const handleSubmit = async (event)=>{
        event.preventDefault()
        let data ={
            'username':username,
            'password':password
        }
        console.log(data)
        //if we're logged out we will be under a different token. Get rid of this header and allow for a new token to be created.
        try{
            let response = await api.post('users/login/',data)
            console.log(response.data)
            const {token} = response.data
            console.log(token)
            localStorage.setItem('token',token)
            api.defaults.headers.common['Authorization'] = `token ${token}`
            navigate('/play')
            console.log('we through!!!!')
        }
        catch(error){
            console.log(error)
            setShowError(true)
            setTimeout(()=>{
                setShowError(false)
            },3000)
        }

    }
    return (
        <>
        <div className="signup-background h-screen">
        <h1 className="text-center">Sign In</h1>
        <div className="text-center flex justify-center">
            
                <Form>
                    <Form.Group className="mb-3" controlId="formBasicUsername">
            <Form.Label>Username</Form.Label>
            <Form.Control onChange={(e)=>setUsername(e.target.value)} type="username" placeholder="Enter username" />
            <Form.Text className="text-muted">
                We'll never share your username with anyone else.
            </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3" controlId="formBasicPassword">
            <Form.Label>Password</Form.Label>
            <Form.Control onChange={(e)=>setPassword(e.target.value)} type="password" placeholder="Password" />
            </Form.Group>
            <Button onClick={handleSubmit} variant="primary" type="submit">
            Submit
            </Button>
        </Form>
        </div>

        {
            showError &&
            <p className="text-center text-red-500 font-bold">user not found!</p>
        }
        </div>
        </>
    )
}