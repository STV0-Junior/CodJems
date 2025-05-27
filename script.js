// script.js
document.addEventListener("DOMContentLoaded", function () {
  // ============ Configurações Gerais ============
  const navbar = document.querySelector(".navbar");
  const hamburger = document.getElementById("hamburger");
  const navLinks = document.getElementById("navLinks");
  const sections = document.querySelectorAll(".page-section");

  // ============ Menu Mobile ============
  hamburger.addEventListener("click", () => {
    navLinks.classList.toggle("active");
  });

  // ============ Controle de Abas ============
  function showSection(targetId) {
    // Esconde todas as seções
    sections.forEach((section) => {
      section.style.display = "none";
    });

    // Mostra a seção alvo
    const targetSection = document.querySelector(targetId);
    if (targetSection) {
      targetSection.style.display = "block";

      // Scroll suave
      window.scrollTo({
        top: targetSection.offsetTop - 80,
        behavior: "smooth",
      });
    }
  }

  // ============ Navegação ============
  function handleNavigation(targetId) {
    // Fechar menu mobile
    navLinks.classList.remove("active");

    // Mostrar seção correspondente
    showSection(targetId);
  }

  // Eventos para todos os links internos
  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener("click", function (e) {
      if (this.hash !== "#") {
        e.preventDefault();
        handleNavigation(this.hash);
      }
    });
  });

  // ============ Inicialização ============
  showSection("#inicio"); // Mostra a seção inicial

  // ============ Controle Especial do WhatsApp ============
  document.querySelectorAll('a[href*="whatsapp.com"]').forEach((button) => {
    button.addEventListener("click", () => {
      navLinks.classList.remove("active");
    });
  });

  // ============ FAQ Accordion ============
  document.querySelectorAll(".faq-question").forEach((question) => {
    question.addEventListener("click", () => {
      const faqItem = question.closest(".faq-item");
      faqItem.classList.toggle("active");

      document.querySelectorAll(".faq-item").forEach((item) => {
        if (item !== faqItem) item.classList.remove("active");
      });
    });
  });

  // ============ Filtro de Projetos ============
  document.querySelectorAll(".filter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      document
        .querySelectorAll(".filter-btn")
        .forEach((btn) => btn.classList.remove("active"));
      button.classList.add("active");

      const filter = button.dataset.filter;
      document.querySelectorAll(".project-card").forEach((card) => {
        card.style.display =
          filter === "all" || card.dataset.category === filter
            ? "block"
            : "none";
      });
    });
  });

  // ============ Validação do Formulário ============
  const form = document.getElementById("indicacaoForm");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();

      let isValid = true;
      const fields = this.querySelectorAll("[required]");

      fields.forEach((field) => {
        if (!field.value.trim()) {
          isValid = false;
          field.style.borderColor = "#ff3860";
        } else {
          field.style.borderColor = "rgba(190, 0, 255, 0.3)";
        }
      });

      // script.js (trecho modificado)
      if (isValid) {
        // Coletar dados do formulário
        const formData = {
          indicador: {
            nome:
              document.getElementById("primeiro-nome").value +
              " " +
              document.getElementById("sobrenome").value,
            email: document.getElementById("email").value,
            whatsapp: document.getElementById("whatsapp").value,
            conheceu:
              document.getElementById("conheceu").options[
                document.getElementById("conheceu").selectedIndex
              ].text,
          },
          indicado: {
            nome:
              document.getElementById("nome-indicado").value +
              " " +
              document.getElementById("sobrenome-indicado").value,
            email: document.getElementById("email-indicado").value,
            whatsapp: document.getElementById("whatsapp-indicado").value,
          },
          projeto: {
            tipo: document.getElementById("tipo-projeto").options[
              document.getElementById("tipo-projeto").selectedIndex
            ].text,
            descricao: document.getElementById("descricao-projeto").value,
          },
        };

        // Construir mensagem para WhatsApp
        const mensagem = `*Nova Indicação Recebida* 

    *Indicador:*
    ▸ Nome: ${formData.indicador.nome}
    ▸ Email: ${formData.indicador.email}
    ▸ WhatsApp: ${formData.indicador.whatsapp}
    ▸ Como conheceu: ${formData.indicador.conheceu}

    *Indicado:*
    ▸ Nome: ${formData.indicado.nome}
    ▸ Email: ${formData.indicado.email}
    ▸ WhatsApp: ${formData.indicado.whatsapp}

    *Projeto:*
    ▸ Tipo: ${formData.projeto.tipo}
    ▸ Descrição: ${formData.projeto.descricao}`;

        // Codificar mensagem para URL
        const mensagemCodificada = encodeURIComponent(mensagem);

        // Seu número de WhatsApp (substitua pelo seu número completo com código do país)
        const seuWhatsapp = "5585992069495"; // Ex: 5511999999999

        // URL do WhatsApp
        const whatsappUrl = `https://wa.me/${seuWhatsapp}?text=${mensagemCodificada}`;

        // Simular envio e redirecionar
        const submitBtn = this.querySelector(".submit-btn");
        submitBtn.disabled = true;
        submitBtn.innerHTML =
          'Enviando... <i class="fas fa-spinner fa-spin"></i>';

        setTimeout(() => {
          submitBtn.innerHTML = 'Enviado! <i class="fas fa-check"></i>';
          setTimeout(() => {
            this.reset();
            submitBtn.disabled = false;
            submitBtn.innerHTML = "ENVIAR INDICAÇÃO";

            // Abrir WhatsApp após 1 segundo
            window.open(whatsappUrl, "_blank");
          }, 2000);
        }, 1500);
      } else {
        alert("Preencha todos os campos obrigatórios!");
      }
    });
  }

  // ============ Validação do Formulário de PEDIDO ============
const formPedido = document.getElementById("pedidoForm");
if (formPedido) {
  formPedido.addEventListener("submit", function (e) {
    e.preventDefault();

    let isValid = true;
    const fields = this.querySelectorAll("[required]");

    // Validação básica
    fields.forEach((field) => {
      if (!field.value.trim()) {
        isValid = false;
        field.style.borderColor = "#ff3860";
      } else {
        field.style.borderColor = "rgba(190, 0, 255, 0.3)";
      }
    });

    if (isValid) {
      // Coletar dados
      const formData = {
        nome: document.getElementById("nome-cliente").value,
        email: document.getElementById("email-cliente").value,
        whatsapp: document.getElementById("whatsapp-cliente").value,
        servico: document.getElementById("tipo-servico").value,
        descricao: document.getElementById("descricao-projeto").value,
        conheceu: document.getElementById("conheceu").value
      };

      // Formatando a mensagem
      const mensagem = `*Novo Pedido de Orçamento*\n
        ▸ *Nome:* ${formData.nome}
        ▸ *Email:* ${formData.email}
        ▸ *WhatsApp:* ${formData.whatsapp}
        ▸ *Serviço:* ${formData.servico}
        ▸ *Como nos conheceu:* ${formData.conheceu}
        \n*Descrição do Projeto:*\n${formData.descricao}`;

      const whatsappUrl = `https://wa.me/5585992069495?text=${encodeURIComponent(mensagem)}`;
      
      const submitBtn = this.querySelector(".submit-btn");
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';
      submitBtn.disabled = true;

      // Simulação de envio
      setTimeout(() => {
        window.open(whatsappUrl, "_blank");
        submitBtn.innerHTML = '<i class="fas fa-check"></i> Enviado!';
        setTimeout(() => {
          this.reset();
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar Solicitação';
        }, 2000);
      }, 1000);
    } else {
      alert("Preencha todos os campos obrigatórios!");
    }
  });
}


  // ============ Efeitos Visuais ============
  document.querySelectorAll(".team-member").forEach((member) => {
    member.addEventListener("mouseenter", () => {
      member.style.transform = "translateY(-10px)";
      member.style.boxShadow = "0 15px 30px rgba(190, 0, 255, 0.2)";
    });
    member.addEventListener("mouseleave", () => {
      member.style.transform = "";
      member.style.boxShadow = "";
    });
  });

  // ============ Controle da Navbar no Scroll ============
  window.addEventListener("scroll", () => {
    navbar.style.background =
      window.scrollY > 50
        ? "linear-gradient(135deg, #1a0521 0%, #1a0521 100%)"
        : "linear-gradient(135deg, #1a0521 0%, #2d0a3a 100%)";

    navbar.style.boxShadow =
      window.scrollY > 50
        ? "0 4px 20px rgba(196, 68, 238, 0.2)"
        : "0 4px 20px rgba(196, 68, 238, 0.1)";
  });

  // ============ Scroll Down Button ============
  const scrollArrow = document.querySelector(".scroll-down-arrow");
  if (scrollArrow) {
    scrollArrow.addEventListener("click", (e) => {
      e.preventDefault();
      handleNavigation("#projetos");
    });

    window.addEventListener("scroll", () => {
      scrollArrow.classList.toggle("hidden", window.scrollY > 200);
    });
  }
});
