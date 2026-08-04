type FooterProps = {
  pushToBottom?: boolean;
};

export default function Footer({ pushToBottom = true }: FooterProps) {
  return (
    <footer
      className={[
        "flex flex-col gap-2 border-t border-slate-200 px-1 pb-1 pt-4 text-xs text-slate-500",
        "md:flex-row md:items-center md:justify-between",
        pushToBottom ? "mt-auto" : "",
      ].join(" ")}
    >
      <div className="space-y-1">
        <p>© {new Date().getFullYear()} Unified Attestation. All rights reserved.</p>
        <p>
          An initiative by{" "}
          <a
            href="https://volla.online/"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-slate-700 transition hover:text-blue-800 hover:underline"
          >
            Volla Systeme GmbH
          </a>{" "}
          <span aria-hidden="true">·</span> Built in Germany
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 md:justify-end">
        <span>
          Designed and developed by{" "}
          <a
            href="https://dorsavalli.com"
            target="_blank"
            rel="noreferrer"
            className="font-semibold text-blue-700 transition hover:text-blue-900 hover:underline"
          >
            Dorsa Valli
          </a>
        </span>
        <a href="https://uattest.net/" className="transition hover:text-slate-900">
          More Info
        </a>
      </div>
    </footer>
  );
}
