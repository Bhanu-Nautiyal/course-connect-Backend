"use client";
import React, { useState } from 'react';
import Image from 'next/image';
import axios from 'axios';

const AdminLogin = ({ onLoginSuccess }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
    
        console.log("Logging in with:", { username, password }); // Debugging line
    
        try {
            const response = await axios.post('http://localhost:8080/login', {
                username,
                password,
            },{
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            if (response.status === 200) {
                const date = new Date();
                date.setTime(date.getTime() + (24 * 60 * 60 * 1000)); // 24 hours
                const expires = "expires=" + date.toUTCString();
                document.cookie = `auth-token=your_token_value; path=/dashboard; ${expires}`;
                onLoginSuccess();
            }
        } catch (err) {
            console.error('Full error object:', err);
            if (err.response) {
                console.error('Error response:', err.response);
                setError(`${err.response.data}`);
            } else if (err.request) {
                console.error('Error request:', err.request);
                setError('No response from server. Please check your connection.');
            } else {
                console.error('Error message:', err.message);
                setError('An error occurred. Please try again.');
            }
        }
    };

    return (
        <div className="font-[poppins] text-[#000000] min-h-screen transition-colors duration-200 ease-in">
        <section className="flex justify-center items-center h-screen">
            <div className="relative w-[22rem] lg:w-[22rem]"> {/* Slightly larger width */}
                <div className="border border-[hsla(0,0%,65%,0.158)] shadow-[0_0_36px_1px_rgba(0,0,0,0.2)] rounded-[10px] backdrop-blur-[20px] z-[99] p-6 md:p-5 lg:p-4"> {/* Adjust padding */}
                    <Image src="/assets/dashboard/login.png" alt="illustration" className="absolute top-[-10%] right-[-2px] w-[85%] lg:w-[80%]" width={500} height={600} /> 
                    <h1 className="text-[2.4rem] md:text-[2.2rem] lg:text-[2rem] opacity-60">LOGIN</h1> {/* Slightly larger heading */}
                    <form onSubmit={handleSubmit}>
                        <input
                            type="text"
                            placeholder="USERNAME"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="block w-full p-[13px] md:p-[12px] lg:p-[10px] my-6 bg-[#9191911f] border-none rounded-[5px] font-medium tracking-[0.8px] text-[15px] lg:text-[14px] backdrop-blur-[15px] outline-none focus:shadow-[0_0_16px_1px_rgba(0,0,0,0.2)]"
                        />
                        <input
                            type="password"
                            placeholder="PASSWORD"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="block w-full p-[13px] md:p-[12px] lg:p-[10px] my-6 bg-[#9191911f] border-none rounded-[5px] font-medium tracking-[0.8px] text-[15px] lg:text-[14px] backdrop-blur-[15px] outline-none focus:shadow-[0_0_16px_1px_rgba(0,0,0,0.2)]"
                        />
                        <button
                            type="submit"
                            className="bg-[#fbbd05] text-[#000000] block w-full py-[13px] md:py-[12px] lg:py-[11px] rounded-[5px] text-[18px] md:text-[17px] lg:text-[16px] tracking-[1.3px] font-bold cursor-pointer mb-6 transition-all duration-100 ease-in-out border-none hover:shadow-[0_0_10px_1px_rgba(0,0,0,0.15)] hover:scale-[1.02] text-center"
                        >
                            SUBMIT
                        </button>
                        {error && <p className="text-red-500 text-center">{error}</p>}
                        <div className="mt-9 lg:mt-7 text-center">
                        <Image src="/assets/header/logo.png" alt="CourseConnect Logo" className="mx-auto mb-2 w-36 sm:w-32 lg:w-30 h-auto" layout="intrinsic" width={144} height={36}/>
                            <p className="text-sm">Copyright © 2024 CourseConnect</p>
                        </div>
                    </form>
                </div>
            </div>
        </section>
    </div>    
    );
};

export default AdminLogin;
