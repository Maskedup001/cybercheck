/**
 * Оглавление юридических страниц.
 *
 * Прогрессивное улучшение: если JS не загрузился, навигация остаётся
 * скрытой (`hidden` в разметке), а страница читается как обычный документ.
 * Якоря генерируются из существующих заголовков, поэтому добавленный
 * раздел автоматически попадает в оглавление.
 */

const toc = document.querySelector('[data-js="legal-toc"]');
const list = document.querySelector('[data-js="legal-toc-list"]');

if (toc && list) {
  const sections = [...document.querySelectorAll(".legal__body .legal__section")].filter(
    (section) => section.querySelector(".legal__section-title"),
  );

  if (sections.length > 0) {
    const links = new Map();
    const fragment = document.createDocumentFragment();

    sections.forEach((section, index) => {
      if (!section.id) section.id = `section-${index + 1}`;

      const heading = section.querySelector(".legal__section-title");
      const link = document.createElement("a");

      link.className = "legal__toc-link";
      link.href = `#${section.id}`;
      link.textContent = heading.textContent.trim();

      const item = document.createElement("li");
      item.append(link);
      fragment.append(item);

      links.set(section.id, link);
    });

    list.append(fragment);
    toc.hidden = false;
    toc.closest(".legal__layout")?.classList.add("legal__layout--with-nav");

    const entries = sections.map((section) => ({
      section,
      id: section.id,
    }));

    const HEADER_OFFSET = 120;
    const LAST_ITEM = entries.length - 1;
    let frame = 0;

    const setCurrent = (id) => {
      for (const [sectionId, link] of links) {
        if (sectionId === id) {
          link.setAttribute("aria-current", "location");
        } else {
          link.removeAttribute("aria-current");
        }
      }
    };

    const update = () => {
      frame = 0;

      let currentId = entries[0].id;

      for (const { section, id } of entries) {
        if (section.getBoundingClientRect().top <= HEADER_OFFSET) {
          currentId = id;
        }
      }

      // В самом низу всегда последний раздел: короткий хвост
      // иначе не дотягивает до отступа и подсветка «залипает».
      const scrollable = document.documentElement.scrollHeight > window.innerHeight + 4;

      if (
        scrollable &&
        window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4
      ) {
        currentId = entries[LAST_ITEM].id;
      }

      setCurrent(currentId);
    };

    const schedule = () => {
      if (frame === 0) frame = window.requestAnimationFrame(update);
    };

    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    window.addEventListener("hashchange", schedule);
    window.addEventListener("load", update);

    update();
  }
}
