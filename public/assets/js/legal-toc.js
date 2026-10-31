/**
 * Оглавление юридических страниц.
 *
 * Прогрессивное улучшение: если JS не загрузился, навигация остаётся
 * скрытой (`hidden` в разметке), а страница читается как обычный документ.
 * Якоря берутся из существующих заголовков, поэтому добавленный раздел
 * сам появляется в оглавлении.
 *
 * Подсветка текущего пункта:
 *  - переход по пункту задаёт раздел явно — это и есть «текущий»;
 *  - скролл-спай подхватывает управление, только если прокрутка реально
 *    различает разделы. На коротком документе (вся страница — один экран)
 *    позиция прокрутки не говорит ничего: любой расчёт упирается в низ
 *    страницы, и подсветка залипает на последнем пункте. Поэтому там
 *    она остаётся за выбранным пунктом.
 */

const toc = document.querySelector('[data-js="legal-toc"]');
const list = document.querySelector('[data-js="legal-toc-list"]');

if (toc && list) {
  const sections = [...document.querySelectorAll(".legal__body .legal__section")].filter(
    (section) => section.querySelector(".legal__section-title"),
  );

  // Оглавление из одного пункта — это не оглавление: оставляем документ
  // одной колонкой, как и без скрипта.
  if (sections.length > 1) {
    /** Линия под верхом экрана: заголовок выше неё считается прочитанным. */
    const ACTIVE_LINE = 120;
    /** Сколько ждём окончания плавной прокрутки, прежде чем отдать
     *  подсветку скроллу. */
    const SETTLE = 700;

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

      // Переход по оглавлению переносит фокус в раздел, иначе следующая
      // табуляция снова начинается с оглавления.
      if (!section.hasAttribute("tabindex")) section.setAttribute("tabindex", "-1");
    });

    list.append(fragment);
    toc.hidden = false;
    toc.closest(".legal__layout")?.classList.add("legal__layout--with-nav");

    const ids = sections.map((section) => section.id);
    const byId = new Map(sections.map((section) => [section.id, section]));

    let frame = 0;
    /** id таймера: пока он жив, подсветкой владеет выбранный пункт. */
    let lock = 0;
    let current = "";

    const root = document.documentElement;

    const maxScroll = () => Math.max(0, root.scrollHeight - root.clientHeight);

    const setCurrent = (id) => {
      if (id === current) return;
      current = id;

      for (const [sectionId, link] of links) {
        if (sectionId === id) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      }
    };

    const hashId = () => {
      const raw = window.location.hash.slice(1);

      if (!raw) return "";

      try {
        const id = decodeURIComponent(raw);
        return byId.has(id) ? id : "";
      } catch {
        return "";
      }
    };

    const spy = () => {
      frame = 0;

      const max = maxScroll();

      // Страница целиком в одном экране — прокручивать нечего.
      if (max <= 0) return;

      // Может ли последний раздел вообще дойти до линии? Если нет,
      // прокрутка не различает разделы: ниже линии они оказываются
      // все разом, и подсветка залипает на последнем. В этом случае
      // подсветкой владеет выбранный пункт; прокрутка возвращает
      // первый пункт только в самом начале страницы.
      const last = sections[sections.length - 1];
      const lastTop = last.getBoundingClientRect().top + window.scrollY;

      if (lastTop - max > ACTIVE_LINE) {
        if (window.scrollY <= 2) setCurrent(ids[0]);
        return;
      }

      let active = ids[0];

      for (const section of sections) {
        if (section.getBoundingClientRect().top <= ACTIVE_LINE) active = section.id;
      }

      setCurrent(active);
    };

    const schedule = () => {
      if (frame === 0) frame = window.requestAnimationFrame(spy);
    };

    const lockCurrent = () => {
      window.clearTimeout(lock);
      lock = window.setTimeout(() => {
        lock = 0;
        schedule();
      }, SETTLE);
    };

    /** Пользователь взялся за прокрутку сам — возвращаем управление спою. */
    const release = () => {
      if (lock === 0) return;
      window.clearTimeout(lock);
      lock = 0;
      schedule();
    };

    const navigate = (id) => {
      const section = byId.get(id);

      if (!section) return;

      setCurrent(id);
      lockCurrent();

      // Хэш нужен, чтобы ссылку можно было скопировать и вернуться к ней.
      if (window.location.hash !== `#${id}`) {
        try {
          window.history.replaceState(null, "", `#${id}`);
        } catch {
          /* Среда без доступа к истории: навигация остаётся рабочей. */
        }
      }

      // Фокус ставим до прокрутки: так он не может прервать её, а
      // следующая табуляция пойдёт по тексту раздела.
      section.focus({ preventScroll: true });
      // scroll-margin-top у раздела отрабатывает и здесь.
      section.scrollIntoView({ block: "start", behavior: "auto" });
    };

    // Переход ведём сами: у браузерного перехода по якорю нет никакого
    // состояния, и если раздел уже в кадре, страница просто не двигается.
    for (const [id, link] of links) {
      link.addEventListener("click", (event) => {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
          return;
        }

        event.preventDefault();
        navigate(id);
      });
    }

    // «Назад»/«Вперёд» и прямые ссылки с якорем.
    window.addEventListener("hashchange", () => {
      const id = hashId();

      if (id) setCurrent(id);
      else schedule();
    });

    window.addEventListener(
      "scroll",
      () => {
        if (lock === 0) schedule();
      },
      { passive: true },
    );
    window.addEventListener("resize", schedule);

    for (const type of ["wheel", "touchmove", "keydown"]) {
      window.addEventListener(type, release, { passive: true });
    }

    setCurrent(hashId() || ids[0]);
    schedule();
  }
}
