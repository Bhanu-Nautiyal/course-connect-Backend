"use client";
import React, { useState, useEffect } from "react";
import { Eye, EyeOff } from 'lucide-react';
import "../globals.css";
import AddCourses from "../components/AddCourses";

const CustomSwitch = ({ isOn, handleToggle }) => (
  <label className="relative inline-flex items-center cursor-pointer">
    <input
      type="checkbox"
      checked={isOn}
      onChange={handleToggle}
      className="sr-only peer"
    />
    <div className="peer ring-0 bg-rose-400 rounded-full outline-none duration-300 after:duration-500 w-6 h-6 shadow-md peer-checked:bg-emerald-500 peer-focus:outline-none after:content-['✖️'] text-[11px] after:rounded-full after:absolute after:outline-none after:h-4 after:w-4 after:bg-gray-50 after:top-1 after:left-1 after:flex after:justify-center after:items-center peer-hover:after:scale-75 peer-checked:after:content-['✔️'] after:-rotate-180 peer-checked:after:rotate-0"></div>
  </label>
);

const DashboardTable = () => {
  const [courseStatuses, setCourseStatuses] = useState({
    Amity_Course: true,
    Manipal_Course: false,
    Jain_Course: true,
  });

  const [blogStatuses, setBlogStatuses] = useState({
    Info_Blog: false,
    Theme_Blog: true,
    Info_Blog2: true,
  });
  const handleCourseToggle = (courseId) => {
    setCourseStatuses((prevStatuses) => ({
      ...prevStatuses,
      [courseId]: !prevStatuses[courseId],
    }));
  };
  const handleBlogToggle = (blogId) => {
    setBlogStatuses((prevStatuses) => ({
      ...prevStatuses,
      [blogId]: !prevStatuses[blogId],
    }));
  };
  return (
    <div>
      <ul className="flex items-center gap-4">
        <li className="text-gray-800">
          <a href="#" className="text-gray-400 pointer-events-none">
            Dashboard
          </a>
        </li>
        <li>
          <i className="fas fa-chevron-right text-gray-800"></i>
        </li>
        <li>
          <a href="#" className="text-blue-500 pointer-events-auto">
            Home
          </a>
        </li>
      </ul>
      <ul className="box-info grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-9">
        {[
          { icon: "fas p-6 fa-book", title: "Total Courses", value: "0" },
          { icon: "fas p-6 fa-pencil-alt", title: "Total Blogs", value: "0" },
        ].map((item, index) => (
          <li
            key={index}
            className="p-6 bg-white rounded-[20px] flex items-center gap-6"
          >
            <i
              className={` ${
                item.icon
              } w-20 h-20 rounded-[10px] text-3xl ${
                index === 0
                  ? "bg-blue-100 text-blue-500"
                  : index === 1
                  ? "bg-yellow-100 text-yellow-500"
                  : "bg-orange-100 text-orange-500"
              }`}
            ></i>
            <span className="text">
              <h3 className="text-2xl font-semibold text-gray-800">
                {item.value}
              </h3>
              <p className="text-gray-800">{item.title}</p>
            </span>
          </li>
        ))}
      </ul>
      <div className="table-data flex flex-wrap gap-6 mt-6 w-full text-gray-800">
        <div className="order flex-grow flex-basis-[500px] rounded-[20px] bg-white p-6 overflow-x-auto">
          <div className="head flex items-center gap-4 mb-6">
            <h3 className="mr-auto text-2xl font-semibold">All Courses</h3>
            <i className="fas fa-search cursor-pointer"></i>
            <i className="fas fa-filter cursor-pointer"></i>
          </div>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  S.No
                </th>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  Course ID
                </th>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(courseStatuses).map(
                ([courseId, status], index) => (
                  <tr key={index} className="hover:bg-gray-100">
                    <td className="py-4 flex items-center gap-3 pl-1.5">
                      <p>{index + 1}</p>
                    </td>
                    <td className="py-4">{courseId}</td>
                    <td className="py-4">
                      <CustomSwitch
                        isOn={status}
                        handleToggle={() => handleCourseToggle(courseId)}
                      />
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
        <div className="todo flex-grow flex-basis-[300px] rounded-[20px] bg-white p-6">
          <div className="head flex items-center gap-4 mb-6">
            <h3 className="mr-auto text-2xl font-semibold">All Blogs</h3>
            <i className="fas fa-search cursor-pointer"></i>
            <i className="fas fa-filter cursor-pointer"></i>
          </div>
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  S.No
                </th>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  Blog ID
                </th>
                <th className="pb-3 text-sm text-left border-b border-gray-200">
                  Status
                </th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(blogStatuses).map(([blogId, status], index) => (
                <tr key={index} className="hover:bg-gray-100">
                  <td className="py-4 flex items-center gap-3 pl-1.5">
                    <p>{index + 1}</p>
                  </td>
                  <td className="py-4">{blogId}</td>
                  <td className="py-4">
                    <CustomSwitch
                      isOn={status}
                      handleToggle={() => handleBlogToggle(blogId)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const AddCourse = () => (
  <div>
    <h1 className="text-3xl font-semibold mb-2.5 text-gray-800">Add Course</h1>
    <AddCourses />
        
  </div>
);


const AddBlogs = () => {
  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-semibold mb-6 text-gray-800">Add Blogs</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Schema Container */}
        <div className="bg-white shadow-md rounded-lg overflow-hidden">
          <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
            <h2 className="text-xl font-semibold text-gray-700">Schema</h2>
          </div>
          <div className="p-4">
            <p className="text-gray-600 mb-4">Add your blog schema here</p>
            <div className="space-y-4">
              <input 
                type="text" 
                placeholder="Title" 
                className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <textarea 
                placeholder="Content" 
                className="w-full p-2 border border-gray-300 rounded h-32 focus:outline-none focus:ring-2 focus:ring-blue-500"
              ></textarea>
              {/* Add more schema fields as needed */}
            </div>
          </div>
        </div>

        {/* Metadata Container */}
        <div className="bg-white shadow-md rounded-lg overflow-hidden">
          <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
            <h2 className="text-xl font-semibold text-gray-700">Metadata</h2>
          </div>
          <div className="p-4">
            <p className="text-gray-600 mb-4">Add metadata for future database use</p>
            <div className="space-y-4">
              <input 
                type="text" 
                placeholder="Author" 
                className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <input 
                type="date" 
                className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <input 
                type="text" 
                placeholder="Tags (comma-separated)" 
                className="w-full p-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {/* Add more metadata fields as needed */}
            </div>
          </div>
        </div>
      </div>

      <button className="mt-6 bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
        Save Blog
      </button>
    </div>
  );
};

const AddAdmin = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    missingCriteria: [],
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordsMatch, setPasswordsMatch] = useState(true);
  const [message, setMessage] = useState('');

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    
    if (name === 'password') {
      checkPasswordStrength(value);
    }
    if (name === 'password' || name === 'confirmPassword') {
      checkPasswordsMatch(name === 'password' ? value : formData.password, name === 'confirmPassword' ? value : formData.confirmPassword);
    }
  };

  const checkPasswordStrength = (password) => {
    const criteria = [
      { regex: /.{8,}/, description: 'at least 8 characters' },
      { regex: /[!@#$%^&*(),.?":{}|<>]/, description: 'a special character' },
      { regex: /\d/, description: 'a number' },
      { regex: /[a-z]/, description: 'a lowercase letter' },
      { regex: /[A-Z]/, description: 'an uppercase letter' },
    ];

    const missingCriteria = criteria.filter((item) => !item.regex.test(password));
    const score = criteria.length - missingCriteria.length;

    setPasswordStrength({ score, missingCriteria });
  };

  const checkPasswordsMatch = (password, confirmPassword) => {
    setPasswordsMatch(password === confirmPassword);
  };

  const getStrengthColor = () => {
    if (passwordStrength.score <= 2) return 'bg-red-500';
    if (passwordStrength.score <= 4) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const togglePasswordVisibility = (field) => {
    if (field === 'password') {
      setShowPassword(!showPassword);
    } else {
      setShowConfirmPassword(!showConfirmPassword);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.password !== formData.confirmPassword) {
      setMessage('Passwords do not match');
      return;
    }

    try {
      const response = await fetch('http://localhost:8080/admin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          password: formData.password,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setMessage('Admin added successfully');
        setFormData({ username: '', email: '', password: '', confirmPassword: '' });
      } else {
        const errorData = await response.json();
        setMessage(errorData.message || 'Error adding admin');
      }
    } catch (error) {
      console.error('Error:', error);
      setMessage('Error connecting to server');
    }
  };

  return (
    <>
      <h1 className="text-3xl font-semibold mb-6 text-gray-800">Add Admin</h1>
      {message && (
        <div className={`mb-4 p-2 ${message.includes('Error') ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'} rounded`}>
          {message}
        </div>
      )}
      <form className="space-y-8" onSubmit={handleSubmit}>
        <div>
          <label htmlFor="username" className="block text-base font-semibold text-gray-700">
            Username
          </label>
          <input
            type="text"
            id="username"
            name="username"
            value={formData.username}
            onChange={handleInputChange}
            className="mt-1 py-1 p-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
          />
        </div>
        <div>
          <label htmlFor="email" className="block text-base font-semibold text-gray-700">
            Email
          </label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleInputChange}
            className="mt-1 py-1 p-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
          />
        </div>
        <div>
          <label htmlFor="password" className="block text-base font-semibold text-gray-700">
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              id="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              className={`mt-1 py-1 p-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 ${
                !passwordsMatch ? 'border-red-500' : ''
              }`}
            />
            <button
              type="button"
              onClick={() => togglePasswordVisibility('password')}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"
            >
              {showPassword ? <EyeOff className="h-5 w-5 text-gray-500" /> : <Eye className="h-5 w-5 text-gray-500" />}
            </button>
          </div>
          {formData.password && (
            <div className="mt-2">
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div className={`h-2.5 rounded-full ${getStrengthColor()}`} style={{ width: `${(passwordStrength.score / 5) * 100}%` }}></div>
              </div>
              {passwordStrength.missingCriteria.length > 0 && (
                <ul className="list-disc list-inside text-sm text-red-600 mt-1">
                  {passwordStrength.missingCriteria.map((item, index) => (
                    <li key={index}>Missing {item.description}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
        <div>
          <label htmlFor="confirmPassword" className="block text-base font-semibold text-gray-700">
            Confirm Password
          </label>
          <div className="relative">
            <input
              type={showConfirmPassword ? "text" : "password"}
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              className={`mt-1 py-1 p-2 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 ${
                !passwordsMatch ? 'border-red-500 focus:ring-red-400 focus:outline-none' : 'focus:ring-green-400 focus:outline-none'
              }`}
            />
            <button
              type="button"
              onClick={() => togglePasswordVisibility('confirmPassword')}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"
            >
              {showConfirmPassword ? <EyeOff className="h-5 w-5 text-gray-500" /> : <Eye className="h-5 w-5 text-gray-500" />}
            </button>
          </div>
          {!passwordsMatch && formData.confirmPassword && (
            <p className="mt-1 text-sm text-red-600">Passwords do not match</p>
          )}
        </div>
        <div>
          <button
            type="submit"
            className="w-30 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Add Admin
          </button>
        </div>
      </form>
    </>
  );
};

const DashboardContent = () => {
  const [activeMenuItem, setActiveMenuItem] = useState("dashboard");
  const [sidebarHidden, setSidebarHidden] = useState(false);
  const [searchFormVisible, setSearchFormVisible] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const handleResize = () => {
      const mobile = window.innerWidth < 768;
      setIsMobile(mobile);
      setSidebarHidden(mobile);
      if (window.innerWidth > 576) {
        setSearchFormVisible(false);
      }
    };

    handleResize(); // Call once to set initial state
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const handleMenuClick = (menuItem) => {
    setActiveMenuItem(menuItem);
  };

  const toggleSidebar = () => {
    setSidebarHidden(!sidebarHidden);
  };
  const menuItems = [
    { name: "Home", icon: "fas fa-home fa-lg", key: "dashboard", showOnMobile: true },
    { name: "Add Course", icon: "fas fa-book fa-lg", key: "fas fa-book fa-lg", showOnMobile: false },
    { name: "Add Blogs", icon: "fas fa-edit fa-lg", key: "fas fa-edit fa-lg", showOnMobile: false },
    { name: "Add Admin", icon: "fas fa-user-plus fa-lg", key: "fas fa-user-plus fa-lg", showOnMobile: true },
  ];

  return (

      <div className="flex bg-gray-100 py- min-h-screen overflow-hidden font-['Poppins',sans-serif]">
      <section
          id="sidebar"
          className={`fixed bg-white z-[20] transition-all duration-300 rounded-r-2xl ${
            sidebarHidden ? "w-[50px]" : "w-[200px]"
          }`}
        >
          <div className="font-bold text-xl h-16 flex items-center text-blue-500 sticky top-0 left-0 bg-white z-[500] pb-5 py-6 px-4 rounded-r-2xl">
            <i
              className="fas fa-bars cursor-pointer text-gray-800"
              onClick={toggleSidebar}
            ></i>
          </div>
          <ul className="side-menu mt-6 px-1">
          {menuItems.map((item) => (
              (!isMobile || item.showOnMobile) && (
                <li
                  key={item.name}
                  className={`h-12 bg-transparent ml-1.5 rounded-l-full p-1 ${
                    activeMenuItem === item.key ? "bg-gray-100 relative" : ""
                  }`}
                >
                  <a
                    href="#"
                    onClick={() => handleMenuClick(item.key)}
                    className={`w-full h-full bg-white flex items-center rounded-full text-base text-gray-800 whitespace-nowrap overflow-x-hidden ${
                      activeMenuItem === item.key ? "text-blue-500" : ""
                    } hover:text-blue-500`}
                  >
                    <i
                      className={`${item.icon} min-w-[40px] flex justify-center`}
                    ></i>
                    <span className={`text ${sidebarHidden ? "hidden" : ""}`}>
                      {item.name}
                    </span>
                  </a>
                </li>
              )
            ))}
          </ul>

          <ul className="side-menu">
            <li
              className={`h-12 bg-transparent ml-1.5 rounded-l-full p-1 ${
                activeMenuItem === "Logout" ? "bg-gray-100" : ""
              }`}
            >
              <a
                href="#"
                onClick={() => handleMenuClick("Logout")}
                className="w-full h-full bg-white flex items-center rounded-full text-base text-red-500 whitespace-nowrap overflow-x-hidden"
              >
                <i className="fas fa-sign-out-alt fa-lg min-w-[40px] px-1 flex justify-center"></i>
                <span className={`text ${sidebarHidden ? "hidden" : ""}`}>
                  Logout
                </span>
              </a>
            </li>
          </ul>
        </section>

        <section
          id="content"
          className={`flex-1 flex flex-col transition-all duration-300 ${
            sidebarHidden ? "ml-[60px]" : "ml-[200px]"
          }`}
        >
          <main className="flex-1 p-6 overflow-y-auto">
            <div className="head-title flex items-center justify-between gap-4 flex-wrap">
              <div className="left">
                {activeMenuItem === "dashboard" && (
                  <h1 className="text-3xl font-semibold mb-2.5 text-gray-800">
                    Dashboard
                  </h1>
                )}
              </div>
            </div>

            {activeMenuItem === "dashboard" && <DashboardTable />}
            {activeMenuItem === "fas fa-book fa-lg" && <AddCourse />}
            {activeMenuItem === "fas fa-edit fa-lg" && <AddBlogs />}
            {activeMenuItem === "fas fa-user-plus fa-lg" && <AddAdmin />}
          </main>
        </section>
      </div>
  );
};

export default DashboardContent;
