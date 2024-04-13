import React from "react";
import {api} from '../utilities'
import { useState } from "react";
const Option = ({text,setChatHistory,setIsLoading})=>{
    const handleDecision = async (event)=>{
        event.preventDefault();
        let data= {
            'prompt':text
        }
        // api.defaults.params['prompt'] = 
       
        try{
            setIsLoading(true)
            let response = await api.post('/prompt/',data)
            setIsLoading(false)
            setChatHistory(response.data)
        }
        catch(error){
            console.log(error)
        }
        
        
        
    }
return(
    <>
    <div onClick= {handleDecision} className="option-background h-[3.5rem] text-black mb-8 hover:cursor-pointer">
        <p>{text}</p>
    </div>
    </>
)
}
export default Option