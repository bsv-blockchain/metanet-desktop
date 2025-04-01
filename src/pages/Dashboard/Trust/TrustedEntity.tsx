/* eslint-disable react/prop-types */
import React, { useState } from 'react'
import { Typography, Box, Slider, DialogContent, DialogContentText, DialogActions, Hidden, IconButton, Button } from '@mui/material'
import Delete from '@mui/icons-material/Close'
import CustomDialog from '../../../components/CustomDialog'
import { Certifier } from '@bsv/wallet-toolbox-client/out/src/WalletSettingsManager'

const TrustedEntity = ({ entity, setTrustedEntities, classes, history }: { history: any, classes: any, setTrustedEntities: Function, entity: Certifier, trustedEntities: Certifier[] }) => {
  const [trust, setTrust] = useState(entity.trust)
  const [deleteOpen, setDeleteOpen] = useState(false)

  const handleTrustChange = (e, v) => {
    setTrust(v)
    setTrustedEntities(old => {
      const newEntities = [...old]
      newEntities[newEntities.indexOf(entity)].trust = v
      return newEntities
    })
  }

  const handleDelete = () => {
    setTrustedEntities(old => {
      const newEntities = [...old]
      newEntities.splice(newEntities.indexOf(entity), 1)
      return newEntities
    })
    setDeleteOpen(false)
  }

  return (
    <>
      <Box
        sx={{ 
          display: 'flex',
          flexDirection: 'column',
          border: '1px solid',
          borderColor: 'divider',
          mb: 2,
          overflow: 'hidden',
          position: 'relative'
        }}
      >
        {/* Delete Button - Positioned absolutely in the top right */}
        <IconButton 
          onClick={() => setDeleteOpen(true)}
          size="small"
          sx={{ 
            position: 'absolute', 
            top: 4, 
            right: 4,
            zIndex: 1
          }}
        >
          <Delete fontSize='small' color='secondary' />
        </IconButton>
        
        {/* Entity Information */}
        <Box
          sx={{ 
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            p: 1.5,
            pb: 0.5,
            pr: 5 // Add padding to the right to make space for the delete button
          }}
        >
          <img src={entity.iconUrl} className={classes.entity_icon} alt={`${entity.name} icon`} />
          <Box>
            <Typography><b>{entity.name}</b></Typography>
            <Typography variant='caption' color='textSecondary'>{entity.description}</Typography>
          </Box>
        </Box>
        
        {/* Trust Slider Controls */}
        <Box 
          sx={{ 
            display: 'flex',
            alignItems: 'center',
            pl: 2,
            pr: 3,
            py: 1,
            gap: 2
          }}
        >
          <Typography sx={{ minWidth: '45px' }}><b>{trust}</b> / 10</Typography>
          <Slider 
            onChange={handleTrustChange} 
            min={0} 
            max={10} 
            step={1} 
            value={trust}
            sx={{ flex: 1 }}
          />
        </Box>
      </Box>
      <CustomDialog title='Delete Trust Relationship' open={deleteOpen} onClose={() => setDeleteOpen(false)}>
        <DialogContent>
          <DialogContentText>Do you want to delete this trust relationship?</DialogContentText>
          <div className={classes.entity_icon_name_grid}>
            <img src={entity.iconUrl} className={classes.entity_icon} alt={`${entity.name} icon`} />
            <div>
              <Typography><b>{entity.name}</b></Typography>
              <Typography variant='caption' color='textSecondary'>{entity.description}</Typography>
            </div>
          </div>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)}>Cancel</Button>
          <Button onClick={handleDelete}>Yes, Delete</Button>
        </DialogActions>
      </CustomDialog>
    </>
  )
}

export default TrustedEntity
