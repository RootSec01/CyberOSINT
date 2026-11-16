export default function Mark({ size = 22 }) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 22 22" fill="none" stroke="var(--brand)" strokeWidth="1.8">
      <path d="M11 2l7 2.5v6c0 4.5-3 7.6-7 9.5-4-1.9-7-5-7-9.5v-6z" />
      <path d="M7.5 11h3l3-3M10.5 11l3 3" />
    </svg>
  );
}
