import React from "react";
import { useState ,useEffect} from "react";
import Option from  './Options'
import Button from 'react-bootstrap/Button';
import { api } from "../utilities";
import axios from "axios";
import DownloadSvg  from  '../pics/download-icon-purple.svg'


export const  ChatMessage =({role,message, setChatHistory, setIsLoading,isLoading,index,length,existingImageUrl,chatHistory})=>{
    // need to separate prompt from options.
    //  / means delimiter for regex expression   \* is escape sequence so i can use *. \d is for numbers [0-9]

    const [option_list,setOptionList] = useState([])
    const [decision,setDecision] = useState('')
    const [prompt,setPrompt] = useState('')
    const [isOptionLoading,setIsOptionLoading] = useState(false)
    const [showImage,setShowImage] = useState(false)
    const [pendingImage,setPendingImage] = useState(false)
    const [imageUrl,setImageUrl] = useState('')
    const [downloadUrl,setDownloadUrl] = useState(null)
    const [violatesSafety,setViolatesSafety] = useState(false)

    
    useEffect(()=>{
        if(existingImageUrl){
            setShowImage(true)
            setImageUrl(existingImageUrl)
        }
    },[existingImageUrl])
   
    const optionsSelector = ()=>{
        if(role=='model'){
            let options = message.split('Option')
            // setOptions(prevOptions=>[...prevOptions,options[1]])
            for(let i =1; i<4; i++){
                setOptionList(prevOptions=>[...prevOptions,options[i]])
            }
            setPrompt(options[0])
      
        }
    }

    useEffect(()=>{
        optionsSelector()
    },[])

    const handleImage = async ()=>{
        
        try{
            setPendingImage(true)
            let response = await api.post('image/')
            setPendingImage(false)
            setImageUrl(response.data)
            setShowImage(true)
        }
        catch(error){
            setPendingImage(false)
            setViolatesSafety(true)
            setTimeout(()=>{
                setViolatesSafety(false)
            },3000)
        }
        
      }

    const copy_img_url = async ()=>{
        fetch(imageUrl)
        .then(res=>res.blob())
        .then(blob=> {
         readFile(blob)
         
         
         
    })
    }

    const readFile = (input)=>{
        const fr = new FileReader()
        let download_icon = document.getElementById('download-icon')
        fr.readAsDataURL(input)
        fr.addEventListener('load',()=>{
            const res = fr.result
            setDownloadUrl(res)
        })
    }
 

   useEffect(()=>{
    copy_img_url()
   })
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
                            return <Option  key ={index} text = {text} setChatHistory = {setChatHistory} setIsLoading = {setIsLoading}/>
})
                    }
                </>
                )

            }

            {
                showImage&&(
                    <div className="flex justify-center">
                        <img className = 'w-1/4 h-1/4'src = {imageUrl}/>
                        <a href = {downloadUrl} download={`image ${index} open adventure game`}>
                        <img  className="h-[2rem] w-[2rem]"  src = {DownloadSvg}/>
                        </a>
                       
                        


                    </div>
                    
                )
            }
           {
          violatesSafety && 
          <p className="text-center text-red-500 font-bold">Gemini flags this for safety.Sorry!</p>
        }

            {
                !showImage && index==length-1  && !isLoading &&(
                    pendingImage?(
                        <p  className="flex justify-center">Pending Image...</p>
                    ):(
                        <div className="flex justify-center">
                            
                            <Button onClick = {handleImage} variant="success">View Image</Button>
                        </div>
                        
                    )
                )
            }
            
        </div>
        </>
    )
}