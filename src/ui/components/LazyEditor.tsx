// CodeMirror is the largest dependency; load it with the first workspace
// rather than on the console page.

import type { ComponentProps, FunctionComponent } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import type { Editor as EditorType } from './Editor.tsx';

type Props = ComponentProps<typeof EditorType>;
let loaded: FunctionComponent<Props> | null = null;

export function LazyEditor(props: Props) {
  const [Comp, setComp] = useState<FunctionComponent<Props> | null>(() => loaded);
  useEffect(() => {
    if (Comp) return;
    let live = true;
    void import('./Editor.tsx').then((m) => {
      loaded = m.Editor as FunctionComponent<Props>;
      if (live) setComp(() => loaded);
    });
    return () => {
      live = false;
    };
  }, []);
  if (!Comp) return <div class="editor editor-loading mono faint small" aria-busy="true">Loading editor…</div>;
  return <Comp {...props} />;
}
