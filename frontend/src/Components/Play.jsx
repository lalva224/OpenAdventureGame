import React from "react";
import { useState,useEffect } from "react";
import { api } from "../utilities";
import { ChatMessage } from "./ChatMessage";
import { data } from "autoprefixer";
import Button from 'react-bootstrap/Button';
import Form from 'react-bootstrap/Form';
const Play = ()=>{
const [chatHistory,setChatHistory] = useState([])
const [decision,setDecision] = useState('')
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
    event.preventDefault();
    let data= {
      'prompt':decision
    }
    // api.defaults.params['prompt'] = formData
    let response = await api.post('/prompt/',data)
    setChatHistory(response.data)
  }
    return (
        <>
        <div className="bg-customColor h-screen text-white">
        <p>Welcome to open adventure game!!</p>
        {
          chatHistory.map((chat,index)=>{
            if(index!=0){
             return <ChatMessage key = {index}role = {chat['role']} message = {chat['parts']}/>
            }
           
})
        }
       
          <Form>
        <Form.Group className="mb-3" >
          <Form.Label>Decision</Form.Label>
          <Form.Control onChange={(e)=>setDecision(e.target.value)} type="input" placeholder="Enter Decision" />
          <Button onClick={handleDecison} variant="primary" type="submit">
          Search
        </Button>
        </Form.Group>


      </Form>
          
        </div>
        </>
    
    )
}

export default Play