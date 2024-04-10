import React from "react";
import { useState,useEffect } from "react";
import { api } from "../utilities";
import { ChatMessage } from "./ChatMessage";
import { data } from "autoprefixer";
import Button from 'react-bootstrap/Button';
import Form from 'react-bootstrap/Form';
import {useNavigate} from 'react-router-dom'


const Play = ()=>{
const [chatHistory,setChatHistory] = useState([])
const [decision,setDecision] = useState('')
const navigate = useNavigate()
const [isLoading,setIsLoading] = useState(false)
  //make initial request

  const StartGame = async()=>{
    let token = localStorage.getItem('token')
    try{
      let response = await api.get('/start/')
      let data = response.data
      setChatHistory(data)

    }
    catch(error){
      console.log(error)
    }
    
  }
  useEffect(()=>{
    //done once
    StartGame()
  },[])

  const handleDecison = async (event)=>{
    event.preventDefault()
    let data= {
      'prompt':decision
    }
    // api.defaults.params['prompt'] = formData
    let response = null
    try{
       response = await api.post('/prompt/',data)
      //from this point is processing request -> loading. Or it throws a 500 error bc of safety
      setIsLoading(true)
    }
    catch(error){
      console.log('flagged for safety!!')
    }
    finally{
      setIsLoading(false)
      setChatHistory(response.data)
    }
    
  
    
  }
  

  const EndGame = async ()=>{
    //need to delete chat history from server AND chat history from React State. Also start a new game.

    //this would delete chat history in server
    let response = await api.delete('endgame/')
    if(response.status=204){
      //delete chat history state
      setChatHistory([])
      console.log('chat history deleted!!')
      //start a new game!!
      StartGame()
    }
  }

  const Logout = async ()=>{
    //this will just delete their session token.
    let response = await api.post('users/logout/')
    //also need to delete token from local storage, at least pre deployment.
    localStorage.removeItem('token')
    //take them to home page.
    navigate('/')

  }
    return (
        <>
        <div className="bg-customColor min-h-screen text-white">

          <nav className="mb-3">
          <h1 className="text-center">Time for an Adventure</h1>
            <p onClick={Logout} className="absolute top-0 right-0  hover:text-blue-500 cursor-pointer">Logout</p>
          </nav>
         
        
        {
          chatHistory.map((chat,index)=>{
            if(index!=0){
             return <ChatMessage key = {index}role = {chat['role']} message = {chat['parts']} setChatHistory = {setChatHistory}/>
            }
           
})
        }
       
          <Form>
          <Form.Label>Wild Card Decision</Form.Label>
        <Form.Group className="mb-3 flex justify-center" >
          <Form.Control onChange={(e)=>setDecision(e.target.value)} type="input" placeholder="Enter Decision" />
          <Button onClick={handleDecison} variant="primary" type="submit">
          Search
        </Button>
        </Form.Group>

      </Form>

      <div className="flex justify-center">
       <Button onClick={EndGame} variant="danger">End Game</Button>
      </div>
      
          
        </div>
        </>
    
    )
}

export default Play