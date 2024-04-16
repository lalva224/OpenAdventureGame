import React from "react";
import {api} from '../utilities'
import { useState } from "react";
const Option = ({text,setChatHistory,setIsLoading})=>{
    const [violatesSafety,setViolatesSafety] = useState(false)
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
            setIsLoading(false)
            setViolatesSafety(true)
            console.log('Safety!!')
            setTimeout(()=>{
                setViolatesSafety(false)
            },3000)
        }
        
        
        
    }
return(
    <>
    <div onClick= {handleDecision} className="option-background h-[3.5rem] text-black mb-8 hover:cursor-pointer">
        <p>{text}</p>
    </div>
    {
          violatesSafety && 
          <p className="text-center text-red-500 font-bold">Gemini flags this for safety.Sorry!</p>
        }
    </>
)
}
export default Option