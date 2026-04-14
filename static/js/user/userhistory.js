function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const main = document.getElementById('main');
    sidebar.classList.toggle('collapsed');
    main.classList.toggle('expanded');
  }

  document.addEventListener('DOMContentLoaded', function() {
    // File table pagination and search
    setupTable('fileSearchInput', 'fileTableBody', 'fileTablePagination', 'filePrevPage', 'fileNextPage', 'fileDisplayCount', 'fileTotalCount', 10);
    
    // Query table pagination and search
    setupTable('querySearchInput', 'queryTableBody', 'queryTablePagination', 'queryPrevPage', 'queryNextPage', 'queryDisplayCount', 'queryTotalCount', 10);
    
    function setupTable(searchInputId, tableBodyId, paginationId, prevPageId, nextPageId, displayCountId, totalCountId, rowsPerPage) {
      const searchInput = document.getElementById(searchInputId);
      const tableBody = document.getElementById(tableBodyId);
      const pagination = document.getElementById(paginationId);
      const prevPage = document.getElementById(prevPageId);
      const nextPage = document.getElementById(nextPageId);
      const displayCount = document.getElementById(displayCountId);
      const totalCount = document.getElementById(totalCountId);
      
      if (!tableBody) return;
      
      const rows = Array.from(tableBody.querySelectorAll('tr'));
      let currentPage = 1;
      const totalPages = Math.ceil(rows.length / rowsPerPage);
      
      // Initialize display
      updateTable();
      updatePagination();
      
      // Search functionality
      if (searchInput) {
        searchInput.addEventListener('input', function() {
          const searchTerm = this.value.toLowerCase();
          const filteredRows = rows.filter(row => {
            return Array.from(row.cells).some(cell => 
              cell.textContent.toLowerCase().includes(searchTerm)
            );
          });
          
          // Reset pagination
          currentPage = 1;
          
          // Update table with filtered rows
          tableBody.innerHTML = '';
          filteredRows.forEach((row, index) => {
            if (index >= (currentPage - 1) * rowsPerPage && index < currentPage * rowsPerPage) {
              tableBody.appendChild(row.cloneNode(true));
            }
          });
          
          // Update pagination
          updatePagination(filteredRows.length);
        });
      }
      
      // Pagination click events
      if (pagination) {
        pagination.addEventListener('click', function(e) {
          if (e.target.tagName === 'A' && e.target.textContent !== 'Previous' && e.target.textContent !== 'Next') {
            e.preventDefault();
            currentPage = parseInt(e.target.textContent);
            updateTable();
            updatePagination();
          }
        });
        
        if (prevPage) {
          prevPage.addEventListener('click', function(e) {
            e.preventDefault();
            if (currentPage > 1) {
              currentPage--;
              updateTable();
              updatePagination();
            }
          });
        }
        
        if (nextPage) {
          nextPage.addEventListener('click', function(e) {
            e.preventDefault();
            if (currentPage < totalPages) {
              currentPage++;
              updateTable();
              updatePagination();
            }
          });
        }
      }
      
      function updateTable() {
        tableBody.innerHTML = '';
        rows.forEach((row, index) => {
          if (index >= (currentPage - 1) * rowsPerPage && index < currentPage * rowsPerPage) {
            tableBody.appendChild(row.cloneNode(true));
          }
        });
        
        if (displayCount) {
          const start = (currentPage - 1) * rowsPerPage + 1;
          const end = Math.min(currentPage * rowsPerPage, rows.length);
          displayCount.textContent = start;
          totalCount.textContent = end;
        }
      }
      
      function updatePagination(filteredCount = rows.length) {
        const totalFilteredPages = Math.ceil(filteredCount / rowsPerPage);
        
        // Update Previous button state
        if (prevPage) {
          if (currentPage === 1) {
            prevPage.classList.add('disabled');
          } else {
            prevPage.classList.remove('disabled');
          }
        }
        
        // Update Next button state
        if (nextPage) {
          if (currentPage >= totalFilteredPages) {
            nextPage.classList.add('disabled');
          } else {
            nextPage.classList.remove('disabled');
          }
        }
        
        // Update page numbers
        const pageLinks = pagination.querySelectorAll('.page-item:not(#filePrevPage):not(#fileNextPage):not(#queryPrevPage):not(#queryNextPage)');
        pageLinks.forEach(item => item.remove());
        
        // Create new page numbers
        for (let i = 1; i <= totalFilteredPages; i++) {
          const li = document.createElement('li');
          li.className = `page-item ${i === currentPage ? 'active' : ''}`;
          
          const a = document.createElement('a');
          a.className = 'page-link';
          a.href = '#';
          a.textContent = i;
          
          li.appendChild(a);
          pagination.insertBefore(li, nextPage);
        }
      }
    }

    // Toggle active class on tab clicks
    const tabButtons = document.querySelectorAll('#historyTab button');
    tabButtons.forEach(button => {
      button.addEventListener('click', function() {
        tabButtons.forEach(btn => btn.classList.remove('active'));
        this.classList.add('active');
      });
    });
  });


