import React from "react";
import { useState ,useEffect} from "react";
import Option from  './Options'
export const  ChatMessage =({role,message, setChatHistory})=>{
    // need to separate prompt from options.
    //  / means delimiter for regex expression   \* is escape sequence so i can use *. \d is for numbers [0-9]

    const [option_list,setOptionList] = useState([])
    const [decision,setDecision] = useState('')
    const [prompt,setPrompt] = useState('')
    const optionsSelector = ()=>{
        if(role=='model'){
            let options = message.split('Option')
            // setOptions(prevOptions=>[...prevOptions,options[1]])
            for(let i =1; i<4; i++){
                setOptionList(prevOptions=>[...prevOptions,options[i]])
            }
            console.log(option_list)
            setPrompt(options[0])
      
        }
    }

    useEffect(()=>{
        optionsSelector()
    },[])
    
    
    return (
        <>
        <div>
            {
                role == 'user'?(
                    <p>Role:{role}: {message}</p>
                ):(
                    //split into fragments the prompt and the options
                <>
                    <p>Role: {role}: {prompt}</p>
                    {
    
                        option_list.map((text,index)=>{
                            return <Option key ={index} text = {text} setChatHistory = {setChatHistory}/>
})
                    }
                </>
                )
            }
            
        </div>
        </>
    )
}