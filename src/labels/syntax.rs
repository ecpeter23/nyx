// NOTE: if we ever start generating this list from grammar JSON,
// switch to `phf` to avoid a giant `match` arm.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
  If,
  InfiniteLoop,
  While,
  For,
  LoopBody,
  CallFn,
  CallMethod,
  CallMacro,
  Break,
  Continue,
  Return,
  Block,
  SourceFile,
  Function,
  MayWrapCall,
  Assignment,
  CallWrapper,
  Trivia,
  Other,
}
