import { useEffect, useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { api } from './utilities'
function App() {
  const [chatHistory,setChatHistory] = useState('')
  const [latestMessage,setLatestMessage] = useState('')
  const [count, setCount] = useState(0)
  useEffect(()=>{
    const fetchData = async()=>{
      try{
        let response = await api.get('/prompt/')
        let data = response.data
        setChatHistory(data["chatHistory"])
        setLatestMessage(data["latestMessage"])
        console.log(data)
      }
      catch(error){
        console.log(error)
      }
      
    }
    fetchData()
  },[])
  return (
    <>
      <div className='flex justify-between'>
        <div>
          <p>{chatHistory}</p>
        </div>
        <div>
          <p>{latestMessage}</p>
        </div>
      </div>
      <p>{chatHistory}</p>
    </>
  )
}

export default App
