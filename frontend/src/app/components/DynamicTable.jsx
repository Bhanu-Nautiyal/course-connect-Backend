import React, { useState } from 'react';

const DynamicMultiTableComponent = () => {
  const [activeTable, setActiveTable] = useState(null);
  const [tableData, setTableData] = useState(
    Array(6).fill().map(() => Array(4).fill().map(() => ({ code: '', subject: '' })))
  );
  const [isTransitioning, setIsTransitioning] = useState(false);

  const handleMouseEnter = (index) => {
    setActiveTable(index);
    if (activeTable !== index) {
      setIsTransitioning(true);
      setTimeout(() => {
        setActiveTable(index); // Set the active table after the transition
        setIsTransitioning(false);
      }, 300); // Match this duration with your CSS transition duration
    }
  };
  
  

  const handleClick = (e, index) => {
    e.preventDefault(); // Prevent default behavior
    // You can add any additional functionality for click here if needed
    console.log(`Semester ${index + 1} clicked`);
  };

  const handleInputChange = (tableIndex, rowIndex, column, value) => {
    const newData = [...tableData];
    newData[tableIndex][rowIndex][column] = value;
    setTableData(newData);
  };

  const handleKeyDown = (tableIndex, rowIndex, column, e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
  
      // Maximum number of rows allowed
      const MAX_ROWS = 6;
  
      // Handle moving focus between columns and rows
      const nextColumn = column === 'code' ? 'subject' : 'code';
      const nextRow = column === 'subject' ? rowIndex + 1 : rowIndex;
  
      // Check if we're on the last row and in the 'subject' column
      if (nextRow === tableData[tableIndex].length && nextColumn === 'code') {
        // If the current table has reached the maximum number of rows
        if (tableData[tableIndex].length >= MAX_ROWS) {
          // Switch focus to the next table (if there's a next table)
          const nextTableIndex = tableIndex + 1;
          if (nextTableIndex < tableData.length) {
            // Focus the first input of the next table
            const firstRow = 0;
            const firstColumn = 'code'; // You can change this to 'subject' if needed
            setActiveTable(nextTableIndex); // Set active table to next one
            setTimeout(() => {
              const nextInput = document.querySelector(
                `table:nth-of-type(${nextTableIndex + 1}) input[name='${firstColumn}']`
              );
              if (nextInput) nextInput.focus(); // Focus on the next table's first input
            }, 0);
          }
          return; // Exit the function to prevent further execution
        } else {
          // Add a new row if we are not at the maximum
          const newData = [...tableData];
          newData[tableIndex].push({ code: '', subject: '' });
          setTableData(newData);
        }
      }
  
      // Find the next input field to focus on
      const nextInput = nextColumn === 'subject'
        ? e.target.parentElement.nextElementSibling?.querySelector('input')
        : e.target.closest('tr').nextElementSibling?.querySelector(`input[name='${nextColumn}']`);
  
      if (nextInput) {
        nextInput.focus();
      }
    }
  };
  

  

  const semesters = ['SEMESTER 1', 'SEMESTER 2', 'SEMESTER 3', 'SEMESTER 4', 'SEMESTER 5', 'SEMESTER 6'];

  return (
    <div className="p-4">
      {/* Horizontal Buttons with hover interaction */}
      <div className="flex space-x-4 mb-4 rounded-lg">
        {semesters.map((semester, index) => (
          <button
          style={{ backgroundColor: activeTable === index ? '#fbbd05' : '#001c54' }}  // Active: amber, Inactive: custom dark blue
          key={index}
          className={`px-4 py-2 rounded-md text-white transition-colors cursor-pointer
            ${activeTable === index ? '' : 'hover:bg-amber-600'}`}  // Amber hover for inactive tables
          onMouseEnter={() => handleMouseEnter(index)}
          onClick={(e) => handleClick(e, index)}
        >
            {semester}
          </button>
        ))}
      </div>

      {/* Table Content */}
      {activeTable !== null && (
        <div className="mt-4">
          <div onMouseEnter={() => handleMouseEnter(activeTable)}>
            <table 
             className={`min-w-full border-collapse border border-gray-300 transition-all duration-500 ease-in-out transform ${isTransitioning ? 'opacity-0 scale-95' : 'opacity-100 scale-100'}`}>
              <thead>
                <tr className="bg-gray-100">
                  <th className="border border-gray-300 px-4 py-2 bg-blue-900 text-white text-center">Code</th>
                  <th className="border border-gray-300 px-4 py-2 bg-blue-900 text-white text-center">Subject</th>
                </tr>
              </thead>
              <tbody>
                {tableData[activeTable].map((row, rowIndex) => (
                  <tr key={rowIndex}>
                    <td className="border border-gray-300 px-4 py-2">
                      <input
                        type="text"
                        name="code"
                        value={row.code}
                        onChange={(e) => handleInputChange(activeTable, rowIndex, 'code', e.target.value)}
                        onKeyDown={(e) => handleKeyDown(activeTable, rowIndex, 'code', e)}
                        className="w-full focus:outline-none focus:ring-2 focus:ring-blue-500 rounded px-2 py-2"
                      />
                    </td>
                    <td className="border border-gray-300 px-4 py-2">
                      <input
                        type="text"
                        name="subject"
                        value={row.subject}
                        onChange={(e) => handleInputChange(activeTable, rowIndex, 'subject', e.target.value)}
                        onKeyDown={(e) => handleKeyDown(activeTable, rowIndex, 'subject', e)}
                        className="w-full focus:outline-none focus:ring-2 focus:ring-blue-500 rounded px-2 py-2"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default DynamicMultiTableComponent;
