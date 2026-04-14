/**
* Template Name: NiceAdmin
* Template URL: https://bootstrapmade.com/nice-admin-bootstrap-admin-html-template/
* Updated: Apr 20 2024 with Bootstrap v5.3.3
* Author: BootstrapMade.com
* License: https://bootstrapmade.com/license/
*/

(function() {
  "use strict";

  /**
   * Easy selector helper function
   */
  const select = (el, all = false) => {
    el = el.trim()
    if (all) {
      return [...document.querySelectorAll(el)]
    } else {
      return document.querySelector(el)
    }
  }

  /**
   * Easy event listener function
   */
  const on = (type, el, listener, all = false) => {
    if (all) {
      select(el, all).forEach(e => e.addEventListener(type, listener))
    } else {
      select(el, all).addEventListener(type, listener)
    }
  }

  /**
   * Easy on scroll event listener 
   */
  const onscroll = (el, listener) => {
    el.addEventListener('scroll', listener)
  }

  /**
   * Sidebar toggle
   */
  if (select('.toggle-sidebar-btn')) {
    on('click', '.toggle-sidebar-btn', function(e) {
      select('body').classList.toggle('toggle-sidebar')
    })
  }

  /**
   * Search bar toggle
   */
  if (select('.search-bar-toggle')) {
    on('click', '.search-bar-toggle', function(e) {
      select('.search-bar').classList.toggle('search-bar-show')
    })
  }

  /**
   * Initialize Bootstrap dropdowns
   */
  document.addEventListener('DOMContentLoaded', function() {
    // Initialize all dropdowns on the page
    var dropdownElementList = [].slice.call(document.querySelectorAll('[data-bs-toggle="dropdown"]'))
    var dropdownList = dropdownElementList.map(function(dropdownToggleEl) {
      return new bootstrap.Dropdown(dropdownToggleEl)
    })
  });

  /**
   * Navbar links active state on scroll
   */
  let navbarlinks = select('#navbar .scrollto', true)
  const navbarlinksActive = () => {
    let position = window.scrollY + 200
    navbarlinks.forEach(navbarlink => {
      if (!navbarlink.hash) return
      let section = select(navbarlink.hash)
      if (!section) return
      if (position >= section.offsetTop && position <= (section.offsetTop + section.offsetHeight)) {
        navbarlink.classList.add('active')
      } else {
        navbarlink.classList.remove('active')
      }
    })
  }
  window.addEventListener('load', navbarlinksActive)
  onscroll(document, navbarlinksActive)

  /**
   * Toggle .header-scrolled class to #header when page is scrolled
   */
  let selectHeader = select('#header')
  if (selectHeader) {
    const headerScrolled = () => {
      if (window.scrollY > 100) {
        selectHeader.classList.add('header-scrolled')
      } else {
        selectHeader.classList.remove('header-scrolled')
      }
    }
    window.addEventListener('load', headerScrolled)
    onscroll(document, headerScrolled)
  }

  /**
   * Back to top button
   */
  let backtotop = select('.back-to-top')
  if (backtotop) {
    const toggleBacktotop = () => {
      if (window.scrollY > 100) {
        backtotop.classList.add('active')
      } else {
        backtotop.classList.remove('active')
      }
    }
    window.addEventListener('load', toggleBacktotop)
    onscroll(document, toggleBacktotop)
  }

  /**
   * Initiate tooltips
   */
  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
  })

  /**
   * Initiate quill editors
   */
  if (select('.quill-editor-default')) {
    new Quill('.quill-editor-default', {
      theme: 'snow'
    });
  }

  if (select('.quill-editor-bubble')) {
    new Quill('.quill-editor-bubble', {
      theme: 'bubble'
    });
  }

  if (select('.quill-editor-full')) {
    new Quill(".quill-editor-full", {
      modules: {
        toolbar: [
          [{
            font: []
          }, {
            size: []
          }],
          ["bold", "italic", "underline", "strike"],
          [{
              color: []
            },
            {
              background: []
            }
          ],
          [{
              script: "super"
            },
            {
              script: "sub"
            }
          ],
          [{
              list: "ordered"
            },
            {
              list: "bullet"
            },
            {
              indent: "-1"
            },
            {
              indent: "+1"
            }
          ],
          ["direction", {
            align: []
          }],
          ["link", "image", "video"],
          ["clean"]
        ]
      },
      theme: "snow"
    });
  }
  /**
   * Initiate Bootstrap validation check
   */
  var needsValidation = document.querySelectorAll('.needs-validation')

  Array.prototype.slice.call(needsValidation)
    .forEach(function(form) {
      form.addEventListener('submit', function(event) {
        if (!form.checkValidity()) {
          event.preventDefault()
          event.stopPropagation()
        }

        form.classList.add('was-validated')
      }, false)
    })

  /**
   * Initiate Datatables
   */
  const datatables = select('.datatable', true)
  datatables.forEach(datatable => {
    new simpleDatatables.DataTable(datatable, {
      perPageSelect: [5, 10, 15, ["All", -1]],
      columns: [{
          select: 2,
          sortSequence: ["desc", "asc"]
        },
        {
          select: 3,
          sortSequence: ["desc"]
        },
        {
          select: 4,
          cellClass: "green",
          headerClass: "red"
        }
      ]
    });
  })

  /**
   * Autoresize echart charts
   */
  const mainContainer = select('#main');
  if (mainContainer) {
    setTimeout(() => {
      new ResizeObserver(function() {
        select('.echart', true).forEach(getEchart => {
          echarts.getInstanceByDom(getEchart).resize();
        })
      }).observe(mainContainer);
    }, 200);
  }

})();



document.addEventListener('DOMContentLoaded', function() {
  // Initialize responsive tables
  initResponsiveTables();
  
  // Add table search functionality
  initTableSearch();
  
  // Add table sorting functionality
  initTableSorting();
});

/**
 * Makes tables responsive by adding data-label attributes for mobile view
 */
function initResponsiveTables() {
  const tables = document.querySelectorAll('.table');
  
  tables.forEach(table => {
    const headerCells = table.querySelectorAll('thead th');
    const headerLabels = Array.from(headerCells).map(th => th.textContent.trim());
    
    // Skip tables that already have data-label attributes
    const hasDataLabels = table.querySelector('tbody td[data-label]');
    if (hasDataLabels) return;
    
    // Add data-label to each cell based on its column header
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      cells.forEach((cell, index) => {
        if (index < headerLabels.length) {
          cell.setAttribute('data-label', headerLabels[index]);
        }
      });
    });
    
    // Add resize listener for horizontal scroll hint
    addTableScrollHint(table);
  });
}

/**
 * Adds a visual hint for tables that can be scrolled horizontally
 */
function addTableScrollHint(table) {
  const tableWrapper = table.closest('.table-responsive');
  if (!tableWrapper) return;
  
  // Create scroll hint element if it doesn't exist
  let scrollHint = tableWrapper.querySelector('.table-scroll-hint');
  if (!scrollHint) {
    scrollHint = document.createElement('div');
    scrollHint.className = 'table-scroll-hint';
    scrollHint.innerHTML = '<span>Scroll horizontally ➝</span>';
    scrollHint.style.cssText = `
      position: absolute;
      bottom: 10px;
      right: 10px;
      background: rgba(0, 0, 0, 0.7);
      color: white;
      padding: 5px 10px;
      border-radius: 3px;
      font-size: 12px;
      opacity: 0;
      transition: opacity 0.3s ease;
      pointer-events: none;
    `;
    tableWrapper.style.position = 'relative';
    tableWrapper.appendChild(scrollHint);
  }
  
  // Show/hide hint based on scrollability
  const checkScrollability = () => {
    if (tableWrapper.scrollWidth > tableWrapper.clientWidth) {
      scrollHint.style.opacity = '1';
      // Auto-hide after 3 seconds
      setTimeout(() => {
        scrollHint.style.opacity = '0';
      }, 3000);
    } else {
      scrollHint.style.opacity = '0';
    }
  };
  
  // Check on resize and initial load
  window.addEventListener('resize', checkScrollability);
  checkScrollability();
  
  // Hide hint when user starts scrolling
  tableWrapper.addEventListener('scroll', () => {
    scrollHint.style.opacity = '0';
  });
}

/**
 * Adds search functionality to tables with search inputs
 */
function initTableSearch() {
  const searchInputs = document.querySelectorAll('.table-search input');
  
  searchInputs.forEach(input => {
    const tableId = input.getAttribute('data-table-id');
    const table = document.getElementById(tableId);
    if (!table) return;
    
    input.addEventListener('keyup', function() {
      const searchTerm = this.value.toLowerCase();
      const rows = table.querySelectorAll('tbody tr');
      
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const display = text.includes(searchTerm) ? '' : 'none';
        row.style.display = display;
      });
      
      // Show empty state if no results
      toggleEmptyState(table, Array.from(rows).every(row => row.style.display === 'none'));
    });
  });
}

/**
 * Shows or hides empty state message
 */
function toggleEmptyState(table, isEmpty) {
  const tableWrapper = table.closest('.table-responsive');
  if (!tableWrapper) return;
  
  let emptyState = tableWrapper.querySelector('.table-empty');
  
  if (isEmpty) {
    if (!emptyState) {
      emptyState = document.createElement('div');
      emptyState.className = 'table-empty';
      emptyState.innerHTML = `
        <i class="bi bi-search"></i>
        <h4>No Results Found</h4>
        <p>Try adjusting your search criteria</p>
      `;
      tableWrapper.appendChild(emptyState);
    }
    table.style.display = 'none';
    emptyState.style.display = 'block';
  } else {
    table.style.display = '';
    if (emptyState) {
      emptyState.style.display = 'none';
    }
  }
}

/**
 * Adds sorting functionality to sortable tables
 */
function initTableSorting() {
  const sortableColumns = document.querySelectorAll('th[data-sortable]');
  
  sortableColumns.forEach(column => {
    // Add sort indicator and styles
    column.style.cursor = 'pointer';
    column.style.position = 'relative';
    const sortIndicator = document.createElement('span');
    sortIndicator.className = 'sort-indicator';
    sortIndicator.innerHTML = ' ↕️';
    sortIndicator.style.fontSize = '12px';
    sortIndicator.style.opacity = '0.5';
    column.appendChild(sortIndicator);
    
    column.addEventListener('click', function() {
      const tableElement = this.closest('table');
      const index = Array.from(this.parentNode.children).indexOf(this);
      const isAsc = this.getAttribute('data-sort-direction') !== 'asc';
      
      // Update sort direction
      this.setAttribute('data-sort-direction', isAsc ? 'asc' : 'desc');
      
      // Reset other columns
      const headers = tableElement.querySelectorAll('th[data-sortable]');
      headers.forEach(header => {
        if (header !== this) {
          header.removeAttribute('data-sort-direction');
          header.querySelector('.sort-indicator').innerHTML = ' ↕️';
          header.querySelector('.sort-indicator').style.opacity = '0.5';
        }
      });
      
      // Update this column's indicator
      sortIndicator.innerHTML = isAsc ? ' ↑' : ' ↓';
      sortIndicator.style.opacity = '1';
      
      // Sort the table
      sortTableByColumn(tableElement, index, isAsc);
    });
  });
}

/**
 * Sorts table by specific column
 */
function sortTableByColumn(table, columnIndex, ascending = true) {
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  
  // Sort the rows
  const sortedRows = rows.sort((a, b) => {
    const cellA = a.querySelectorAll('td')[columnIndex].textContent.trim();
    const cellB = b.querySelectorAll('td')[columnIndex].textContent.trim();
    
    // Check if values are numbers
    const numA = parseFloat(cellA);
    const numB = parseFloat(cellB);
    
    if (!isNaN(numA) && !isNaN(numB)) {
      return ascending ? numA - numB : numB - numA;
    }
    
    // Otherwise compare as strings
    return ascending 
      ? cellA.localeCompare(cellB) 
      : cellB.localeCompare(cellA);
  });
  
  // Remove existing rows
  rows.forEach(row => {
    tbody.removeChild(row);
  });
  
  // Add sorted rows
  sortedRows.forEach(row => {
    tbody.appendChild(row);
  });
  
  // Add zebra striping
  sortedRows.forEach((row, index) => {
    row.classList.remove('even', 'odd');
    row.classList.add(index % 2 === 0 ? 'even' : 'odd');
  });
}

/**
 * Shows loading state while table data is loading
 */
function showTableLoading(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  
  const tableWrapper = table.closest('.table-responsive');
  if (!tableWrapper) return;
  
  // Hide table
  table.style.display = 'none';
  
  // Create loading state
  let loadingState = tableWrapper.querySelector('.table-loading');
  if (!loadingState) {
    loadingState = document.createElement('div');
    loadingState.className = 'table-loading';
    tableWrapper.appendChild(loadingState);
  }
  
  loadingState.style.display = 'flex';
}

/**
 * Hides loading state and shows table
 */
function hideTableLoading(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  
  const tableWrapper = table.closest('.table-responsive');
  if (!tableWrapper) return;
  
  // Show table
  table.style.display = '';
  
  // Hide loading state
  const loadingState = tableWrapper.querySelector('.table-loading');
  if (loadingState) {
    loadingState.style.display = 'none';
  }
}

/**
 * Initializes a simple pagination for tables
 */
function initTablePagination(tableId, rowsPerPage = 10) {
  const table = document.getElementById(tableId);
  if (!table) return;
  
  const tableWrapper = table.closest('.table-responsive');
  if (!tableWrapper) return;
  
  const rows = table.querySelectorAll('tbody tr');
  const totalPages = Math.ceil(rows.length / rowsPerPage);
  
  // Return if not enough rows to paginate
  if (totalPages <= 1) return;
  
  // Create pagination container
  let pagination = tableWrapper.querySelector('.table-pagination');
  if (!pagination) {
    pagination = document.createElement('div');
    pagination.className = 'table-pagination';
    tableWrapper.after(pagination);
  }
  
  // Current page (starting at 1)
  let currentPage = 1;
  
  // Update pagination UI
  const updatePagination = () => {
    // Clear pagination
    pagination.innerHTML = '';
    
    // Previous button
    const prevBtn = document.createElement('button');
    prevBtn.className = 'btn btn-sm';
    prevBtn.innerHTML = '← Previous';
    prevBtn.disabled = currentPage === 1;
    prevBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        updateTable();
        updatePagination();
      }
    });
    pagination.appendChild(prevBtn);
    
    // Page info
    const pageInfo = document.createElement('span');
    pageInfo.className = 'page-info';
    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    pagination.appendChild(pageInfo);
    
    // Next button
    const nextBtn = document.createElement('button');
    nextBtn.className = 'btn btn-sm';
    nextBtn.innerHTML = 'Next →';
    nextBtn.disabled = currentPage === totalPages;
    nextBtn.addEventListener('click', () => {
      if (currentPage < totalPages) {
        currentPage++;
        updateTable();
        updatePagination();
      }
    });
    pagination.appendChild(nextBtn);
  };
  
  // Update visible table rows
  const updateTable = () => {
    const start = (currentPage - 1) * rowsPerPage;
    const end = start + rowsPerPage;
    
    rows.forEach((row, index) => {
      row.style.display = (index >= start && index < end) ? '' : 'none';
    });
    
    // Scroll to top of table
    tableWrapper.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  
  // Initialize
  updateTable();
  updatePagination();
}
