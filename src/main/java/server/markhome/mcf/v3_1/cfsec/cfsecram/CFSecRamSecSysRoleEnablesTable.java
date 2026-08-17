
// Description: Java 25 in-memory RAM DbIO implementation for SecSysRoleEnables.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSysRoleEnablesTable in-memory RAM DbIO implementation
 *	for SecSysRoleEnables.
 */
public class CFSecRamSecSysRoleEnablesTable
	implements ICFSecSecSysRoleEnablesTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecSysRoleEnablesPKey,
				CFSecBuffSecSysRoleEnables > dictByPKey
		= new HashMap< ICFSecSecSysRoleEnablesPKey,
				CFSecBuffSecSysRoleEnables >();
	private Map< CFSecBuffSecSysRoleEnablesBySysRoleIdxKey,
				Map< CFSecBuffSecSysRoleEnablesPKey,
					CFSecBuffSecSysRoleEnables >> dictBySysRoleIdx
		= new HashMap< CFSecBuffSecSysRoleEnablesBySysRoleIdxKey,
				Map< CFSecBuffSecSysRoleEnablesPKey,
					CFSecBuffSecSysRoleEnables >>();
	private Map< CFSecBuffSecSysRoleEnablesByNameIdxKey,
				Map< CFSecBuffSecSysRoleEnablesPKey,
					CFSecBuffSecSysRoleEnables >> dictByNameIdx
		= new HashMap< CFSecBuffSecSysRoleEnablesByNameIdxKey,
				Map< CFSecBuffSecSysRoleEnablesPKey,
					CFSecBuffSecSysRoleEnables >>();

	public CFSecRamSecSysRoleEnablesTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysRoleEnables ensureRec(ICFSecSecSysRoleEnables rec) {
		return (((CFSecBuffSecSysRoleEnablesFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysRoleEnables createSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables iBuff )
	{
		final String S_ProcName = "createSecSysRoleEnables";
		
		CFSecBuffSecSysRoleEnables Buff = (CFSecBuffSecSysRoleEnables)ensureRec(iBuff);
		CFSecBuffSecSysRoleEnablesPKey pkey = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		pkey.setRequiredSecSysRoleId(Buff.getRequiredSecSysRoleId());
		pkey.setRequiredEnableName(Buff.getRequiredEnableName());
		pkey.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );
		pkey.setRequiredEnableName( Buff.getRequiredEnableName() );
		Buff.setRequiredContainerSysRole( pkey.getRequiredSecSysRoleId() );
		Buff.setRequiredParentEnableGroup( pkey.getRequiredEnableName() );
		Buff.setRequiredSecSysRoleId( pkey.getRequiredSecSysRoleId() );
		Buff.setRequiredEnableName( pkey.getRequiredEnableName() );
		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey keySysRoleIdx = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();
		keySysRoleIdx.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleEnablesByNameIdxKey keyNameIdx = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();
		keyNameIdx.setRequiredEnableName( Buff.getRequiredEnableName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecSysRoleEnablesSysRole",
						"SecSysRoleEnablesSysRole",
						"SecSysRole",
						"SecSysRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictSysRoleIdx;
		if( dictBySysRoleIdx.containsKey( keySysRoleIdx ) ) {
			subdictSysRoleIdx = dictBySysRoleIdx.get( keySysRoleIdx );
		}
		else {
			subdictSysRoleIdx = new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictBySysRoleIdx.put( keySysRoleIdx, subdictSysRoleIdx );
		}
		subdictSysRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysRoleEnables.CLASS_CODE) {
				CFSecBuffSecSysRoleEnables retbuff = ((CFSecBuffSecSysRoleEnables)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysRoleEnables readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		String EnableName )
	{
		{	ICFLibKeyHash256 testSecSysRoleId = SecSysRoleId;
			if (testSecSysRoleId == null) {
				return( null );
			}
		}
		{	String testEnableName = EnableName;
			if (testEnableName == null) {
				return( null );
			}
		}
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredEnableName( EnableName );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecSysRoleEnables readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readDerived";
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredEnableName( PKey.getRequiredEnableName() );
		ICFSecSecSysRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleEnables lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.lockDerived";
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredEnableName( PKey.getRequiredEnableName() );
		ICFSecSecSysRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleEnables[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readAllDerived";
		ICFSecSecSysRoleEnables[] retList = new ICFSecSecSysRoleEnables[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysRoleEnables > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysRoleEnables[] readDerivedBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readDerivedBySysRoleIdx";
		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey key = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();

		key.setRequiredSecSysRoleId( SecSysRoleId );
		ICFSecSecSysRoleEnables[] recArray;
		if( dictBySysRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictSysRoleIdx
				= dictBySysRoleIdx.get( key );
			recArray = new ICFSecSecSysRoleEnables[ subdictSysRoleIdx.size() ];
			Iterator< CFSecBuffSecSysRoleEnables > iter = subdictSysRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictSysRoleIdx
				= new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictBySysRoleIdx.put( key, subdictSysRoleIdx );
			recArray = new ICFSecSecSysRoleEnables[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysRoleEnables[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readDerivedByNameIdx";
		CFSecBuffSecSysRoleEnablesByNameIdxKey key = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();

		key.setRequiredEnableName( EnableName );
		ICFSecSecSysRoleEnables[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecSysRoleEnables[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecSysRoleEnables > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdictNameIdx
				= new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecSysRoleEnables[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysRoleEnables readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readDerivedByIdIdx() ";
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredEnableName( EnableName );
		ICFSecSecSysRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleEnables readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		String EnableName )
	{
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredEnableName( EnableName );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecSysRoleEnables readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readRec";
		ICFSecSecSysRoleEnables buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleEnables lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysRoleEnables buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleEnables[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readAllRec";
		ICFSecSecSysRoleEnables buff;
		ArrayList<ICFSecSecSysRoleEnables> filteredList = new ArrayList<ICFSecSecSysRoleEnables>();
		ICFSecSecSysRoleEnables[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleEnables[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSysRoleEnables buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecSysRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysRoleEnables readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readRecByIdIdx() ";
		ICFSecSecSysRoleEnables buff = readDerivedByIdIdx( Authorization,
			SecSysRoleId,
			EnableName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
			return( (ICFSecSecSysRoleEnables)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysRoleEnables[] readRecBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readRecBySysRoleIdx() ";
		ICFSecSecSysRoleEnables buff;
		ArrayList<ICFSecSecSysRoleEnables> filteredList = new ArrayList<ICFSecSecSysRoleEnables>();
		ICFSecSecSysRoleEnables[] buffList = readDerivedBySysRoleIdx( Authorization,
			SecSysRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysRoleEnables)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleEnables[0] ) );
	}

	@Override
	public ICFSecSecSysRoleEnables[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnables.readRecByNameIdx() ";
		ICFSecSecSysRoleEnables buff;
		ArrayList<ICFSecSecSysRoleEnables> filteredList = new ArrayList<ICFSecSecSysRoleEnables>();
		ICFSecSecSysRoleEnables[] buffList = readDerivedByNameIdx( Authorization,
			EnableName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleEnables.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysRoleEnables)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleEnables[0] ) );
	}

	/**
	 *	Read a page array of the specific SecSysRoleEnables buffer instances identified by the duplicate key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageRecBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		ICFLibKeyHash256 priorSecSysRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecBySysRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSysRoleEnables buffer instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String EnableName,
		ICFLibKeyHash256 priorSecSysRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysRoleEnables updateSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables iBuff )
	{
		CFSecBuffSecSysRoleEnables Buff = (CFSecBuffSecSysRoleEnables)ensureRec(iBuff);
		CFSecBuffSecSysRoleEnablesPKey pkey = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		pkey = (CFSecBuffSecSysRoleEnablesPKey)Buff.getPKey();
		CFSecBuffSecSysRoleEnables existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysRoleEnables",
				"Existing record not found",
				"Existing record not found",
				"SecSysRoleEnables",
				"SecSysRoleEnables",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysRoleEnables",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey existingKeySysRoleIdx = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();
		existingKeySysRoleIdx.setRequiredSecSysRoleId( existing.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey newKeySysRoleIdx = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();
		newKeySysRoleIdx.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleEnablesByNameIdxKey existingKeyNameIdx = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();
		existingKeyNameIdx.setRequiredEnableName( existing.getRequiredEnableName() );

		CFSecBuffSecSysRoleEnablesByNameIdxKey newKeyNameIdx = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();
		newKeyNameIdx.setRequiredEnableName( Buff.getRequiredEnableName() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecSysRoleEnables",
						"Container",
						"Container",
						"SecSysRoleEnablesSysRole",
						"SecSysRoleEnablesSysRole",
						"SecSysRole",
						"SecSysRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySysRoleIdx.get( existingKeySysRoleIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySysRoleIdx.containsKey( newKeySysRoleIdx ) ) {
			subdict = dictBySysRoleIdx.get( newKeySysRoleIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictBySysRoleIdx.put( newKeySysRoleIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNameIdx.get( existingKeyNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
			subdict = dictByNameIdx.get( newKeyNameIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysRoleEnablesTable.deleteSecSysRoleEnables() ";
		CFSecBuffSecSysRoleEnables Buff = (CFSecBuffSecSysRoleEnables)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecSysRoleEnablesPKey pkey = (CFSecBuffSecSysRoleEnablesPKey)(Buff.getPKey());
		CFSecBuffSecSysRoleEnables existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysRoleEnables",
				pkey );
		}
		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey keySysRoleIdx = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();
		keySysRoleIdx.setRequiredSecSysRoleId( existing.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleEnablesByNameIdxKey keyNameIdx = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();
		keyNameIdx.setRequiredEnableName( existing.getRequiredEnableName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecSysRoleEnablesPKey, CFSecBuffSecSysRoleEnables > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySysRoleIdx.get( keySysRoleIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSysRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysRoleId,
		String EnableName )
	{
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredEnableName( EnableName );
		deleteSecSysRoleEnablesByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		CFSecBuffSecSysRoleEnablesPKey key = (CFSecBuffSecSysRoleEnablesPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredEnableName( PKey.getRequiredEnableName() );
		CFSecBuffSecSysRoleEnablesPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysRoleEnables cur;
		LinkedList<CFSecBuffSecSysRoleEnables> matchSet = new LinkedList<CFSecBuffSecSysRoleEnables>();
		Iterator<CFSecBuffSecSysRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleEnables)(schema.getTableSecSysRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecSysRoleEnables( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysRoleEnablesBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysRoleId )
	{
		CFSecBuffSecSysRoleEnablesBySysRoleIdxKey key = (CFSecBuffSecSysRoleEnablesBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newBySysRoleIdxKey();
		key.setRequiredSecSysRoleId( argSecSysRoleId );
		deleteSecSysRoleEnablesBySysRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleEnablesBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesBySysRoleIdxKey argKey )
	{
		CFSecBuffSecSysRoleEnables cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysRoleEnables> matchSet = new LinkedList<CFSecBuffSecSysRoleEnables>();
		Iterator<CFSecBuffSecSysRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleEnables)(schema.getTableSecSysRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecSysRoleEnables( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName )
	{
		CFSecBuffSecSysRoleEnablesByNameIdxKey key = (CFSecBuffSecSysRoleEnablesByNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleEnables().newByNameIdxKey();
		key.setRequiredEnableName( argEnableName );
		deleteSecSysRoleEnablesByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesByNameIdxKey argKey )
	{
		CFSecBuffSecSysRoleEnables cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysRoleEnables> matchSet = new LinkedList<CFSecBuffSecSysRoleEnables>();
		Iterator<CFSecBuffSecSysRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleEnables)(schema.getTableSecSysRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecSysRoleEnables( Authorization, cur );
		}
	}
}
