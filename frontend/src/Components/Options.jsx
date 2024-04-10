import React from "react";
import {api} from '../utilities'
const Option = ({text,setChatHistory})=>{
    const handleDecision = async (event)=>{
        event.preventDefault();
        let data= {
            'prompt':text
        }
        // api.defaults.params['prompt'] = formData
        let response = await api.post('/prompt/',data)
        setChatHistory(response.data)
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