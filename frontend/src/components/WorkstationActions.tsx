import { useApiAction } from '../lib/api'
import { text } from '../lib/format'
import { ErrorNotice, Icon, useNotice } from './UI'
import type { Data } from '../types'

export function CorrelateButton() {
  const action = useApiAction<Data>('/correlation/run')
  const notice = useNotice()
  return <div className="action-with-feedback"><button className="button primary" disabled={action.isPending} onClick={() => action.mutate({}, { onSuccess: result => notice(`Correlation completed. ${text(result, 'Risk assessments are up to date.')}`) })}><Icon name="refresh" />{action.isPending ? 'Correlating evidence…' : 'Correlate & update risk'}</button><ErrorNotice error={action.error} /></div>
}

export function DemoButton() {
  const action = useApiAction('/demo')
  const notice = useNotice()
  return <div className="action-with-feedback"><button className="button" disabled={action.isPending} onClick={() => action.mutate({}, { onSuccess: () => notice('Synthetic ExampleCorp demo is ready. Its advisory records are examples, not real-world vulnerability claims.') })}>{action.isPending ? 'Loading synthetic demo…' : 'Load synthetic demo'}</button><p className="field-help">First load requires an empty inventory. Existing records are never overwritten.</p><ErrorNotice error={action.error} /></div>
}
