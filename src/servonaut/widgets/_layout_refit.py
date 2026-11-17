"""Keep resize-driven fitters working when layout updates sizes without a Resize event."""

from __future__ import annotations

from textual.geometry import Size


class LayoutRefitMixin:
    """Re-run a widget's fit hook when layout changes its dimensions.

    Textual's compositor can lazily rebuild its full widget map before a
    reflow pass (for instance when navigation toggles after scrolling),
    leaving ``reflow`` with no geometry delta to emit ``Resize`` even though
    ``Widget._size_updated`` still observes the new dimensions.
    """

    _layout_refit_pending: bool = False
    _fitted_dimensions: tuple[Size, Size] | None = None

    def _refit_for_layout(self) -> None:
        """Refit widget content for the dimensions updated by layout."""

    def _mark_layout_fitted(self) -> None:
        """Record the dimensions already fitted by a direct resize or fit call."""
        self._fitted_dimensions = (self._size, self._container_size)

    def _size_updated(
        self,
        size: Size,
        virtual_size: Size,
        container_size: Size,
        layout: bool = True,
    ) -> bool:
        size_changed = self._size != size or self._container_size != container_size
        changed = super()._size_updated(size, virtual_size, container_size, layout=layout)
        if layout and size_changed and not self._layout_refit_pending:
            self._layout_refit_pending = True
            self.call_after_refresh(self._run_layout_refit)
        return changed

    def _run_layout_refit(self) -> None:
        self._layout_refit_pending = False
        if not getattr(self, "is_attached", False):
            return
        current = (self._size, self._container_size)
        if self._fitted_dimensions == current:
            return
        self._refit_for_layout()
