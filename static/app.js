/**
 * Next-Gen HRMS Core Client Engine
 * Pure Vanilla JS (ES6+) Architecture
 */

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------------------
    // 1. SYSTEM INITIALIZATION & TOAST WRAPPERS
    // -------------------------------------------------------------------------
    const toastElement = document.getElementById('systemToast');
    let systemToast = null;

    if (toastElement) {
        systemToast = new bootstrap.Toast(toastElement, { delay: 5000 });
    }

    /**
     * Triggers the display of the enterprise glassmorphic toast notification component.
     * @param {string} message - The textual content to deliver.
     * @param {('success'|'danger'|'warning'|'info')} type - Security severity notification context.
     */
    window.showSystemToast = (message, type = 'info') => {
        if (!toastElement || !systemToast) return;

        const iconMap = {
            success: 'fa-circle-check',
            danger: 'fa-triangle-exclamation',
            warning: 'fa-circle-exclamation',
            info: 'fa-circle-info'
        };

        // Reset and apply context-driven color wrappers
        toastElement.className = `toast align-items-center text-white border-0 glass-card bg-${type}-glow`;
        document.getElementById('toastIcon').className = `fa-solid ${iconMap[type] || iconMap.info} text-${type}`;
        document.getElementById('toastMessage').innerText = message;

        systemToast.show();
    };

    // -------------------------------------------------------------------------
    // 2. PASSWORD VISIBILITY INTERACTIVE TOGGLES
    // -------------------------------------------------------------------------
    document.querySelectorAll('.btn-toggle-password').forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordField = document.getElementById(targetId);
            if (!passwordField) return;

            const icon = this.querySelector('i');
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });
    });

    // -------------------------------------------------------------------------
    // 3. CRYPTOGRAPHIC PASSWORD STRENGTH MATRIX METER
    // -------------------------------------------------------------------------
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('strengthMeterBar');
    const strengthText = document.getElementById('strengthMeterText');

    if (passwordInput && strengthBar && strengthText) {
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            let score = 0;

            if (val.length >= 8) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[a-z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[^A-Za-z0-9]/.test(val)) score++;

            // Evaluate mapping output visuals
            let width = '0%';
            let colorClass = 'bg-danger';
            let statusPhrase = 'None';

            if (val.length > 0) {
                switch(score) {
                    case 1:
                    case 2:
                        width = '25%';
                        colorClass = 'bg-danger';
                        statusPhrase = 'Weak Matrix Integrity';
                        break;
                    case 3:
                        width = '50%';
                        colorClass = 'bg-warning';
                        statusPhrase = 'Moderate / Acceptable';
                        break;
                    case 4:
                        width = '75%';
                        colorClass = 'bg-info';
                        statusPhrase = 'Strong Parameter Shield';
                        break;
                    case 5:
                        width = '100%';
                        colorClass = 'bg-success';
                        statusPhrase = 'High-Grade Industrial Guard';
                        break;
                }
            }

            strengthBar.className = `progress-bar transition-all ${colorClass}`;
            strengthBar.style.width = width;
            strengthText.innerText = `Cryptographic Strength: ${statusPhrase}`;
        });
    }

    // -------------------------------------------------------------------------
    // 4. CLIENT SIDE INPUT VALIDATION & DOUBLE-SUBMIT PERIMETER
    // -------------------------------------------------------------------------
    const clientFormIds = ['loginForm', 'registerForm', 'forgotForm', 'resetForm', 'resendForm'];
    
    clientFormIds.forEach(formId => {
        const formElement = document.getElementById(formId);
        if (!formElement) return;

        formElement.addEventListener('submit', function(e) {
            let formIsValid = true;

            // Handle default HTML5 basic validation structures
            if (!this.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
                formIsValid = false;
            }

            // Custom Password Match Validation for Register and Reset contexts
            if (formId === 'registerForm' || formId === 'resetForm') {
                const pass = document.getElementById('password').value;
                const confirmPass = document.getElementById('confirm_password').value;

                if (pass !== confirmPass) {
                    e.preventDefault();
                    window.showSystemToast('Credential mismatch. Configuration verification inputs must match.', 'danger');
                    formIsValid = false;
                }
            }

            this.classList.add('was-validated');

            if (formIsValid) {
                // Engage loader animation signals and block multi-postback spamming
                const submitBtn = this.querySelector('#submitBtn');
                const spinner = this.querySelector('#loadingSpinner');
                
                if (submitBtn) {
                    submitBtn.disabled = true;
                }
                if (spinner) {
                    spinner.classList.remove('d-none');
                }
            }
        });
    });
});