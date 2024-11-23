"use client";
import '@fortawesome/fontawesome-free/css/all.min.css';
import DynamicTableComponent from './DynamicTable';
import React, { useRef, useEffect } from 'react';

function AddCourses() {
  const inputRefs = useRef({});

  useEffect(() => {
    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach((input) => {
      inputRefs.current[input.id] = input;
    });
  }, []);

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const inputs = Object.values(inputRefs.current);
      const currentIndex = inputs.indexOf(e.target);
      const nextInput = inputs[currentIndex + 1];
      if (nextInput) {
        nextInput.focus();
      }
    }
  };

  return (
    <form className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="space-y-8">
        <div className="sm:col-span-4 pb-5">
          <label htmlFor="coursename" className="block text-lg font-bold text-gray-900">
            Course Title
          </label>
          <div className="mt-2">
            <input
              id="coursename"
              name="coursename"
              type="text"
              placeholder="Course title"
              autoComplete="coursename"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
              onKeyPress={handleKeyPress}
            />
          </div>
        </div>

        <div className="mb-4">
          <label htmlFor="category" className="block text-sm font-medium text-gray-700 mb-2">
            University
          </label>
          <select
            id="category"
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
            onKeyPress={handleKeyPress}
          >
            <option>Select University</option>
            <option>Amity University</option>
            <option>Billing</option>
            <option>Technical</option>
            <option>Account</option>
          </select>
        </div>

        <div className="col-span-full pb-10">
          <label htmlFor="cover-photo" className="block text-lg font-bold leading-6 text-gray-900">
            Brochure
          </label>
          <div className="mt-2 flex bg-white justify-center rounded-lg border border-dashed border-gray-900/25 px-6 py-10">
            <div className="text-center">
              <i className="fas fa-file-alt fa-2x text-gray-300 mx-auto"></i>
              <div className="mt-4 flex flex-col sm:flex-row text-sm leading-6 text-gray-600">
                <label
                  htmlFor="pdf-upload"
                  className="relative cursor-pointer rounded-md bg-white font-semibold text-indigo-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-indigo-600 focus-within:ring-offset-2 hover:text-indigo-500"
                >
                  <span>Upload Brochure</span>
                  <input id="pdf-upload" name="pdf-upload" type="file" accept=".pdf" className="sr-only" />
                </label>
                <p className="pl-1 mt-2 sm:mt-0">or drag and drop</p>
              </div>
              <p className="text-xs leading-5 text-gray-600">PNG, JPG, GIF up to 10MB</p>
            </div>
          </div>
        </div>

        <h2 className="text-lg font-bold leading-7 text-gray-900">Banner Information</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <div>
            <label htmlFor="Batch-start" className="block text-base font-semibold leading-6 text-gray-900">
              Batch Start
            </label>
            <div className="mt-2">
              <input
                id="Batch-start"
                name="Batch-start"
                type="date"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>

          <div>
            <label htmlFor="emi" className="block text-base font-semibold leading-6 text-gray-900">
              EMI-Amount
            </label>
            <div className="mt-2">
              <input
                id="emi"
                name="emi"
                type="number"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>

          <div>
            <label htmlFor="Avg-salary" className="block text-base font-semibold leading-6 text-gray-900">
              Average Salary
            </label>
            <div className="mt-2">
              <input
                id="Avg-Salary"
                name="Avg-Salary"
                type="number"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>

          <div>
            <label htmlFor="review" className="block text-base font-semibold leading-6 text-gray-900">
              Reviews
            </label>
            <div className="mt-2">
              <input
                id="review"
                name="review"
                type="number"
                placeholder='number of reviews'
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>
        </div>

        <div className="col-span-full">
          <label htmlFor="course-overview" className="block text-lg font-bold leading-6 text-gray-900">
            Course Overview
          </label>
          <div className="mt-2">
            <textarea
              id="course-overview"
              name="course-overview"
              rows={10}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
              onKeyPress={handleKeyPress}
              defaultValue={''}
            />
          </div>
        </div>

        <div className="col-span-full">
          <label htmlFor="course-highlight" className="block text-lg font-bold leading-6 text-gray-900">
            Course Highlight
          </label>
          <div className="mt-2">
            <textarea
              id="course-highlight"
              name="course-highlight"
              rows={10}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
              defaultValue={''}
              onKeyPress={handleKeyPress}
            />
          </div>
        </div>

        <h2 className="text-lg font-bold leading-7 text-gray-900">Course Benefits</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {[1, 2, 3, 4].map((num) => (
            <div key={num}>
              <label htmlFor={`course-benefits-${num}`} className="block text-lg font-bold leading-6 text-gray-900">
                Course Benefits-{num}
              </label>
              <div className="mt-2">
                <textarea
                  id={`course-benefits-${num}`}
                  name={`course-benefits-${num}`}
                  rows={10}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                  defaultValue={''}
                  onKeyPress={handleKeyPress}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="col-span-full">
          <label htmlFor="eligibility" className="block text-lg font-bold leading-6 text-gray-900">
            Eligibility
          </label>
          <div className="mt-2">
            <textarea
              id="eligibility"
              name="eligibility"
              rows={10}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
              defaultValue={''}
              onKeyPress={handleKeyPress}
            />
          </div>
        </div>

        <div className="col-span-full">
          <label htmlFor="sample" className="block text-lg font-bold leading-6 text-gray-900">
            Sample Certificate
          </label>
          <div className="mt-2 flex bg-white justify-center rounded-lg border border-dashed border-gray-900/25 px-6 py-10">
            <div className="text-center">
              <i className="bx bx-camera bx-lg text-gray-300 mx-auto"></i>
              <div className="mt-4 flex flex-col sm:flex-row text-sm leading-6 text-gray-600">
                <label
                  htmlFor="sample"
                  className="relative cursor-pointer rounded-md bg-white font-semibold text-indigo-600 focus-within:outline-none focus-within:ring-2 focus-within:ring-indigo-600 focus-within:ring-offset-2 hover:text-indigo-500"
                >
                  <span>Upload Sample Certificate</span>
                  <input id="sample" name="sample" type="file" className="sr-only" onKeyPress={handleKeyPress}/>
                </label>
                <p className="pl-1 mt-2 sm:mt-0">or drag and drop</p>
              </div>
              <p className="text-xs leading-5 text-gray-600">PNG, JPG, GIF up to 10MB</p>
            </div>
          </div>
        </div>

        <DynamicTableComponent />

        <h2 className="text-lg font-bold leading-7 text-gray-900">Professional Profile</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          <div>
            <label htmlFor="position" className="block text-base font-semibold leading-6 text-gray-900">
              Position
            </label>
            <div className="mt-2">
              <input
                id="position"
                name="position"
                type="text"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>

          <div>
            <label htmlFor="description" className="block text-base font-semibold leading-6 text-gray-900">
              Description
            </label>
            <div className="mt-2">
              <input
                id="description"
                name="description"
                type="text"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>

          <div>
            <label htmlFor="stu-avg-salary" className="block text-base font-semibold leading-6 text-gray-900">
              Average Salary
            </label>
            <div className="mt-2">
              <input
                id="stu-avg-Salary"
                name="stu-avg-Salary"
                type="number"
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500"
                onKeyPress={handleKeyPress}
              />
            </div>
          </div>
        </div>

        <div className="col-span-full pb-10">
          <label htmlFor="top-recruiter" className="block text-lg font-bold leading-6 text-gray-900">
            Top Recruiter
          </label>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-4">
            {Array.from({ length: 8 }).map((_, index) => (
              <div
                key={index}
                className="mt-2 flex bg-white justify-center items-center rounded-full border border-dashed border-gray-900/25 p-4"
              >
                <div className="text-center">
                  <i className="fas fa-camera fa-sm text-gray-300 mx-auto"></i>
                  <div className="mt-2 flex flex-col text-xs leading-4 text-gray-600">
                    <label
                      htmlFor={`top-recruiter-${index}`}
                      className="relative cursor-pointer rounded-md bg-white font-semibold text-indigo-600 focus:ring focus:ring-indigo-200 focus:border-indigo-500 hover:text-indigo-500"
                    >
                      <span>Upload</span>
                      <input id={`top-recruiter-${index}`} name="top-recruiter" type="file" className="sr-only" />
                    </label>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <h2 className="text-2xl font-semibold text-gray-800 mb-6">Add New FAQ</h2>
        {[1, 2, 3, 4].map((num) => (
          <div key={num} className="mb-4">
            <label htmlFor={`question${num}`} className="block text-sm font-medium text-gray-700 mb-2">Question {num}</label>
            <input 
              type="text" 
              id={`question${num}`} 
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500" 
              placeholder="Enter FAQ question"
              onKeyPress={handleKeyPress}
            />
           <label htmlFor={`answer${num}`} className="block text-sm font-medium text-gray-700 mb-2 mt-4">Answer {num}</label>
            <textarea 
              id={`answer${num}`} 
              rows="4" 
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring focus:ring-indigo-200 focus:border-indigo-500" 
              placeholder="Enter the FAQ answer"
              onKeyPress={handleKeyPress}
            ></textarea>
          </div>
        ))}

        <div className="mt-6 flex flex-col sm:flex-row items-center justify-end gap-4">
          <button type="button" className="w-full sm:w-auto px-4 py-2 text-sm font-semibold text-gray-900 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50">
            Cancel
          </button>
          <button
            type="submit"
            className="w-full sm:w-auto px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          >
            Save
          </button>
        </div>
      </div>
    </form>
  );
}

export default AddCourses;